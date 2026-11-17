"""Structured diagnostic tracing with mandatory secret redaction.

A :class:`EventTrace` records the four kinds of evidence the laboratory is
built to correlate:

* *events* -- h11 events produced/consumed and adapter-level milestones;
* *states* -- the h11 role-state pair after each step;
* *buffer ownership* -- where each byte currently lives (network chunk,
  h11 receive buffer, delivered to business logic, or tunnel handover);
* *connection decisions* -- policy verdicts and pool/reuse decisions.

Sensitive material never enters a trace verbatim: request/response header
values on the redaction list are replaced, and tunnel payloads are recorded
only as length plus a short digest prefix.  The recorded wire transcript is
therefore safe to keep alongside the test that generated it.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import h11
from h11._headers import Headers

__all__ = [
    "REDACTED_HEADERS",
    "redact_headers",
    "describe_event",
    "EventTrace",
    "byte_digest",
]


# Header names (lowercase) whose values must never appear in evidence.
REDACTED_HEADERS = frozenset(
    {
        b"authorization",
        b"proxy-authorization",
        b"cookie",
        b"set-cookie",
        b"www-authenticate",
        b"proxy-authenticate",
    }
)

REDACTION = b"<redacted>"


def redact_headers(headers: Headers) -> List[Tuple[str, str]]:
    """Return a JSON-safe header list with sensitive values removed."""
    out: List[Tuple[str, str]] = []
    for name, value in headers:
        name_l = name.lower()
        if name_l in REDACTED_HEADERS:
            out.append((name_l.decode("ascii"), REDACTION.decode("ascii")))
        else:
            out.append((name_l.decode("ascii"), value.decode("ascii", "replace")))
    return out


def byte_digest(data: bytes) -> str:
    """Short, non-reversible fingerprint for tunnel/body byte accounting."""
    return hashlib.sha256(data).hexdigest()[:16]


def describe_event(event: h11.Event) -> Dict[str, Any]:
    """JSON-safe description of an h11 event; never includes raw secrets."""
    if isinstance(event, h11.Request):
        return {
            "kind": "Request",
            "method": event.method.decode("ascii"),
            "target": event.target.decode("ascii", "replace"),
            "http_version": event.http_version.decode("ascii"),
            "headers": redact_headers(event.headers),
        }
    if isinstance(event, h11.InformationalResponse):
        return {
            "kind": "InformationalResponse",
            "status_code": event.status_code,
            "headers": redact_headers(event.headers),
        }
    if isinstance(event, h11.Response):
        return {
            "kind": "Response",
            "status_code": event.status_code,
            "http_version": event.http_version.decode("ascii"),
            "headers": redact_headers(event.headers),
        }
    if isinstance(event, h11.Data):
        payload = bytes(event.data)
        return {
            "kind": "Data",
            "length": len(payload),
            "digest": byte_digest(payload),
        }
    if isinstance(event, h11.EndOfMessage):
        return {
            "kind": "EndOfMessage",
            "headers": redact_headers(event.headers),
        }
    if isinstance(event, h11.ConnectionClosed):
        return {"kind": "ConnectionClosed"}
    return {"kind": type(event).__name__}


def _state_name(state: Any) -> str:
    return getattr(state, "__name__", repr(state))


@dataclass
class EventTrace:
    """Append-only diagnostic log for one replay run."""

    scenario: str
    fragmentation: str
    entries: List[Dict[str, Any]] = field(default_factory=list)
    # Byte-accounting ledger, updated by the controller:
    bytes_received: int = 0
    bytes_http_delivered: int = 0
    bytes_tunnel_handed_over: int = 0
    http_delivery_count: int = 0
    tunnel_handover_count: int = 0  # ownership transfers; always 0 or 1
    tunnel_delivery_count: int = 0  # individual post-handover chunk deliveries

    def record(
        self,
        step: str,
        *,
        states: Optional[Dict[Any, Any]] = None,
        detail: Optional[Dict[str, Any]] = None,
        buffer_len: Optional[int] = None,
        chunk_len: Optional[int] = None,
    ) -> None:
        entry: Dict[str, Any] = {"seq": len(self.entries), "step": step}
        if states is not None:
            entry["states"] = {
                _state_name(role): _state_name(state)
                for role, state in states.items()
            }
        if buffer_len is not None:
            entry["h11_receive_buffer_bytes"] = buffer_len
        if chunk_len is not None:
            entry["network_chunk_bytes"] = chunk_len
        if detail:
            entry["detail"] = detail
        self.entries.append(entry)

    def record_event(self, step: str, event: h11.Event, conn: h11.Connection) -> None:
        self.record(
            step,
            states=conn.states,
            detail={"event": describe_event(event)},
            buffer_len=len(conn._receive_buffer),  # noqa: SLF001 - evidence needs it
        )

    def record_sentinel(
        self, step: str, sentinel: Any, conn: h11.Connection
    ) -> None:
        self.record(
            step,
            states=conn.states,
            detail={"sentinel": _state_name(sentinel)},
            buffer_len=len(conn._receive_buffer),  # noqa: SLF001
        )

    def record_decision(self, step: str, decision: Any) -> None:
        self.record(
            step,
            detail={
                "decision": {
                    "allowed": decision.allowed,
                    "mode": decision.mode,
                    "target": decision.target,
                    "reason": decision.reason,
                }
            },
        )

    def account_http_delivery(self, data: bytes) -> None:
        self.bytes_http_delivered += len(data)
        self.http_delivery_count += 1

    def account_tunnel_handover(self, data: bytes) -> None:
        self.bytes_tunnel_handed_over += len(data)
        self.tunnel_delivery_count += 1

    def account_handover_transfer(self) -> None:
        """Record the single moment ownership moves from h11 to the tunnel."""
        self.tunnel_handover_count += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario": self.scenario,
            "fragmentation": self.fragmentation,
            "byte_ledger": {
                "received": self.bytes_received,
                "http_delivered": self.bytes_http_delivered,
                "tunnel_handed_over": self.bytes_tunnel_handed_over,
                "http_delivery_count": self.http_delivery_count,
                "tunnel_handover_count": self.tunnel_handover_count,
                "tunnel_delivery_count": self.tunnel_delivery_count,
            },
            "entries": self.entries,
        }
