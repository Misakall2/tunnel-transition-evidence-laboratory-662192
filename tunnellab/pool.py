"""Connection pool with switch-aware lifetime rules.

The pool only ever holds connections that completed a full ordinary exchange
in a reusable state.  Switched connections are excluded *permanently* -- a
tunnelled connection can never re-enter HTTP message handling -- and failed
or closing connections are discarded.  Pool entries carry no trust context:
each new exchange binds a fresh :class:`TrustContext` via the controller, so
identity from a previous target cannot bleed across exchanges.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional

from .controller import ConnectionController
from .trace import EventTrace

__all__ = ["PooledConnection", "ConnectionPool"]


@dataclass
class PooledConnection:
    controller: ConnectionController
    authority: str  # connection-level target for host-scoped reuse
    trace: EventTrace
    uses: int = 0


class ConnectionPool:
    def __init__(self) -> None:
        self._idle: Dict[str, List[PooledConnection]] = {}
        self._retired: List[str] = []  # reasons, for evidence
        self.active: Dict[str, ConnectionController] = {}

    def acquire(self, authority: str, trace: EventTrace) -> Optional[PooledConnection]:
        idle = self._idle.get(authority)
        if idle:
            entry = idle.pop()
            if entry.controller.reusable_for_next_request():
                trace.record(
                    "pool.acquire_reused",
                    states=entry.controller.conn.states,
                    detail={"authority": authority, "uses": entry.uses + 1},
                )
                self.active[authority] = entry.controller
                return entry
            # Should be impossible, but never trust a stale entry.
            self._retire(entry, "stale entry failed reuse check")
        return None

    def register_active(
        self, authority: str, controller: ConnectionController, trace: EventTrace
    ) -> PooledConnection:
        self.active[authority] = controller
        entry = PooledConnection(controller=controller, authority=authority, trace=trace)
        return entry

    def release(self, entry: PooledConnection) -> None:
        """Return a connection to the pool, or retire it.

        Decision is derived solely from the controller's verified state --
        never from what the caller hopes happened.
        """
        controller = entry.controller
        self.active.pop(entry.authority, None)
        if controller.is_switched or controller.is_permanently_closed:
            self._retire(
                entry,
                "switched" if controller.is_switched else "closed-or-failed",
            )
            return
        if not controller.reusable_for_next_request():
            self._retire(entry, "not in DONE/DONE reusable state")
            return
        entry.uses += 1
        self._idle.setdefault(entry.authority, []).append(entry)
        entry.trace.record(
            "pool.returned_idle",
            states=controller.conn.states,
            detail={"authority": entry.authority, "uses": entry.uses},
        )

    def _retire(self, entry: PooledConnection, reason: str) -> None:
        self._retired.append(f"{entry.authority}: {reason}")
        entry.trace.record(
            "pool.retired",
            states=entry.controller.conn.states,
            detail={"authority": entry.authority, "reason": reason},
        )

    @property
    def idle_count(self) -> int:
        return sum(len(v) for v in self._idle.values())

    @property
    def retirements(self) -> List[str]:
        return list(self._retired)

    def idle_authorities(self) -> List[str]:
        return sorted(self._idle.keys())
