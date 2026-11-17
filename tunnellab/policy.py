"""Trust policy that gates every protocol-switch decision.

h11 itself only tracks *whether* a switch was proposed and accepted on the
wire.  Whether this particular client is allowed to tunnel to this authority
or to adopt this upgrade token is a trust decision that belongs to the
calling application.  The diagnostic adapter makes that decision explicit:
no target and no upgrade mode can be reached unless the configured
:class:`SwitchPolicy` allows it for the current request context.
"""

from dataclasses import dataclass, field
from typing import AbstractSet, List, Optional, Tuple

import h11
from h11._headers import Headers

__all__ = [
    "PolicyDecision",
    "SwitchPolicy",
    "TrustContext",
    "extract_switch_request",
]

# Switch modes the adapter understands.
CONNECT = "connect"
UPGRADE = "upgrade"


@dataclass(frozen=True)
class TrustContext:
    """The trusted, caller-supplied identity bound to one exchange.

    A fresh context is created per request; it is never reused across
    exchanges, so authority/identity from a previous target cannot leak into
    the next one (see ``controller.ConnectionController._bind``).
    """

    client_id: str
    allowed_authorities: AbstractSet[str] = field(default_factory=frozenset)
    allowed_upgrades: AbstractSet[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    mode: Optional[str]
    target: Optional[str]
    reason: str

    @property
    def denied(self) -> bool:
        return not self.allowed


def _header_values(headers: Headers, name: bytes) -> Tuple[bytes, ...]:
    found: List[bytes] = []
    for key, value in headers:
        if key == name:
            found.extend(part.strip() for part in value.split(b","))
    return tuple(found)


def extract_switch_request(request: h11.Request) -> Tuple[Optional[str], Tuple[bytes, ...]]:
    """Return ``(mode, upgrade_tokens)`` implied by a request, if any."""
    upgrades = _header_values(request.headers, b"upgrade")
    if request.method == b"CONNECT":
        return CONNECT, upgrades
    if upgrades:
        return UPGRADE, upgrades
    return None, ()


class SwitchPolicy:
    """Allow-list policy for CONNECT targets and Upgrade tokens.

    The default policy denies everything, so an adapter cannot tunnel
    anywhere unless its caller explicitly configures trust.  All checks are
    pure functions of the *current* :class:`TrustContext` and the concrete
    request being sent; there is no mutable global allow-list.
    """

    def __init__(
        self,
        default_authorities: Optional[AbstractSet[str]] = None,
        default_upgrades: Optional[AbstractSet[str]] = None,
    ) -> None:
        self._default_authorities = frozenset(default_authorities or ())
        self._default_upgrades = frozenset(default_upgrades or ())

    def review_request(
        self, context: TrustContext, request: h11.Request
    ) -> PolicyDecision:
        """Decide whether the switch proposed by ``request`` may be sent."""
        mode, upgrades = extract_switch_request(request)
        if mode is None:
            return PolicyDecision(True, None, None, "ordinary request, no switch")

        authorities = frozenset(context.allowed_authorities) or self._default_authorities
        allowed_upgrades = (
            frozenset(context.allowed_upgrades) or self._default_upgrades
        )

        if mode == CONNECT:
            # CONNECT target is the request-target authority (host:port).
            target = request.target.decode("ascii").lower()
            if target not in {a.lower() for a in authorities}:
                return PolicyDecision(
                    False, CONNECT, target,
                    f"CONNECT target {target!r} not in trusted authority set",
                )
            # A CONNECT carrying Upgrade tokens needs the tokens trusted too.
            untrusted = {u.decode("ascii", "replace") for u in upgrades} - {
                u.lower() for u in allowed_upgrades
            }
            if upgrades and untrusted:
                return PolicyDecision(
                    False, UPGRADE, target,
                    f"upgrade token(s) {sorted(untrusted)!r} not trusted",
                )
            return PolicyDecision(True, CONNECT, target, "CONNECT authorized")

        # mode == UPGRADE
        target = request.target.decode("ascii", "replace")
        tokens = {u.decode("ascii", "replace").lower() for u in upgrades}
        trusted = {u.lower() for u in allowed_upgrades}
        untrusted = tokens - trusted
        if untrusted:
            return PolicyDecision(
                False, UPGRADE, target,
                f"upgrade token(s) {sorted(untrusted)!r} not trusted",
            )
        return PolicyDecision(
            True, UPGRADE, target,
            f"upgrade {sorted(tokens)!r} authorized",
        )

    def review_server_acceptance(
        self,
        context: TrustContext,
        mode: str,
        target: Optional[str],
        event: h11.Event,
    ) -> PolicyDecision:
        """Decide whether an *accepting* server event may trigger handover.

        This re-checks trust at the moment of the switch so a server response
        cannot upgrade a connection that the current context never asked for.
        h11 already rejects unsolicited switches at the state-machine level;
        this is the application-level check layered on top.
        """
        if mode == CONNECT:
            if not isinstance(event, h11.Response) or not (
                200 <= event.status_code < 300
            ):
                return PolicyDecision(
                    False, CONNECT, target, "server did not accept CONNECT"
                )
        elif mode == UPGRADE:
            if not isinstance(event, h11.InformationalResponse) or (
                event.status_code != 101
            ):
                return PolicyDecision(
                    False, UPGRADE, target, "server did not return 101"
            )
        else:  # pragma: no cover - defensive
            return PolicyDecision(False, mode, target, "unknown switch mode")
        # Re-run the original request-level review against the same context.
        return PolicyDecision(True, mode, target, "server acceptance authorized")
