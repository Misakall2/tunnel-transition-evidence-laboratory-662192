"""The correct h11 integration adapter under diagnostic examination.

``ConnectionController`` wraps a single :class:`h11.Connection` in CLIENT
role plus a :class:`~tunnellab.transport.MemoryTransport`, and enforces the
boundary rules that a proxy-side adapter must get right:

* switch decisions are bound to a per-request :class:`TrustContext` and go
  through :class:`~tunnellab.policy.SwitchPolicy` before any byte is sent;
* while h11 is in ``MIGHT_SWITCH_PROTOCOL`` / ``SWITCHED_PROTOCOL`` the
  adapter never feeds bytes back into the message parser;
* on a successful switch, ``trailing_data`` is drained **once** and handed
  to the tunnel sink together with every byte read afterwards;
* a rejected switch stays on the ordinary HTTP path until its full response
  has been consumed;
* directional EOF and read failures produce explicit outcomes instead of
  silent truncation;
* switched connections leave the reuse pool forever; failed exchanges
  release all per-exchange state before the next bind.

The controller is deliberately small and synchronous: every rule is
exercised offline by the replay suite in ``tunnellab_tests``.
"""

from dataclasses import dataclass, field
from typing import Callable, List, Optional

import h11

from .policy import (
    CONNECT,
    UPGRADE,
    PolicyDecision,
    SwitchPolicy,
    TrustContext,
    extract_switch_request,
)
from .trace import EventTrace, byte_digest
from .transport import MemoryTransport, ReadFailure

__all__ = [
    "Outcome",
    "Handover",
    "ConnectionController",
    "SwitchRejected",
    "ExchangeFailed",
]


class SwitchRejected(Exception):
    """The trust policy refused to let this request propose a switch."""

    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


class ExchangeFailed(Exception):
    """The exchange ended abnormally.

    ``stage`` names the phase where it failed; ``cause`` is the underlying
    exception (h11 protocol error or injected transport failure).
    """

    def __init__(self, stage: str, cause: BaseException) -> None:
        super().__init__(f"{stage}: {cause!r}")
        self.stage = stage
        self.cause = cause


@dataclass
class Handover:
    """The single, complete tunnel handover for a successful switch."""

    mode: str
    target: Optional[str]
    prefix: bytes  # bytes that arrived in the same read as the switch response
    eof_seen: bool
    # Exactly one Handover is ever produced per connection.
    produced: bool = field(default=False)


@dataclass
class Outcome:
    """Terminal result of pumping one exchange."""

    kind: str  # "complete" | "switched" | "closed" | "failed"
    response: Optional[h11.Event] = None
    body: bytes = b""
    failure_stage: Optional[str] = None
    error: Optional[str] = None
    handover: Optional[Handover] = None
    reusable: bool = False

    @property
    def failed(self) -> bool:
        return self.kind == "failed"


# Internal per-exchange binding. Kept in one object so failure paths can
# discard it atomically -- nothing from a previous target survives.
@dataclass
class _Binding:
    context: TrustContext
    mode: Optional[str]
    target: Optional[str]
    decision: PolicyDecision
    response_complete: bool = False
    request_complete: bool = True
    switched: bool = False
    handover_done: bool = False
    body_parts: List[bytes] = field(default_factory=list)
    response: Optional[h11.Event] = None


class ConnectionController:
    def __init__(
        self,
        transport: MemoryTransport,
        policy: SwitchPolicy,
        trace: EventTrace,
        tunnel_sink: Optional[Callable[[bytes], None]] = None,
    ) -> None:
        self._transport = transport
        self._policy = policy
        self._trace = trace
        self._conn = h11.Connection(h11.CLIENT)
        self._binding: Optional[_Binding] = None
        self._tunnel_sink = tunnel_sink or (lambda data: None)
        self._tunnel_bytes: List[bytes] = []
        self._permanently_closed = False
        self._eof_reported = False
        # Tunnel mode is a one-way latch: once set it is never cleared, so the
        # parser never re-enters message handling regardless of binding state.
        self._tunnel_mode = False
        self._tunnel_terminal = False

    # -- properties used by the pool and assertions -----------------------

    @property
    def conn(self) -> h11.Connection:
        return self._conn

    @property
    def binding(self) -> Optional[_Binding]:
        return self._binding

    @property
    def tunnel_bytes(self) -> bytes:
        return b"".join(self._tunnel_bytes)

    @property
    def is_switched(self) -> bool:
        return self._tunnel_mode

    @property
    def is_permanently_closed(self) -> bool:
        return self._permanently_closed

    def reusable_for_next_request(self) -> bool:
        """A connection may start another exchange only when the previous
        exchange finished cleanly, keep-alive still holds, no switch
        occurred, and no failure left the parser in ERROR.

        After a normal completion the controller has already called
        ``start_next_cycle`` (recycling h11 to IDLE/IDLE) and released the
        binding; either IDLE/IDLE or DONE/DONE with no binding is reusable.
        """
        if self._permanently_closed or self.is_switched:
            return False
        if self._binding is not None:
            return False
        states = self._conn.states
        return states in (
            {h11.CLIENT: h11.DONE, h11.SERVER: h11.DONE},
            {h11.CLIENT: h11.IDLE, h11.SERVER: h11.IDLE},
        )

    # -- request side ------------------------------------------------------

    def submit_request(
        self,
        context: TrustContext,
        request: h11.Request,
        body: bytes = b"",
    ) -> PolicyDecision:
        """Validate, serialize and write one request.

        The policy is consulted *before* any byte touches the transport, so a
        disallowed CONNECT/Upgrade can never leave the client.
        """
        if self._permanently_closed:
            raise ExchangeFailed("submit", RuntimeError("connection permanently closed"))
        if self._binding is not None:
            raise ExchangeFailed("submit", RuntimeError("exchange already in progress"))

        decision = self._policy.review_request(context, request)
        self._trace.record_decision("policy.review_request", decision)
        if decision.denied:
            # Nothing was sent; no binding is retained; caller keeps full
            # control of the (untouched) connection.
            raise SwitchRejected(decision)

        mode, _tokens = extract_switch_request(request)
        self._binding = _Binding(
            context=context, mode=mode, target=decision.target, decision=decision
        )
        try:
            wire = self._conn.send(request)
            self._trace.record_event("send.request", request, self._conn)
            self._transport.write(wire)
            if body:
                data_wire = self._conn.send(h11.Data(data=body))
                self._transport.write(data_wire)
                self._trace.record(
                    "send.data",
                    states=self._conn.states,
                    detail={"length": len(body)},
                )
            eom_wire = self._conn.send(h11.EndOfMessage())
            self._transport.write(eom_wire)
            self._binding.request_complete = True
            self._trace.record_event("send.end_of_message", h11.EndOfMessage(), self._conn)
        except Exception as exc:  # parser-side failure: poison and release
            self._fail("send", exc)
        return decision

    # -- receive side ------------------------------------------------------

    def pump_until_outcome(self, max_iterations: int = 10_000) -> Outcome:
        """Drive reads + h11 parsing until the exchange reaches a terminal
        state: full ordinary response, tunnel handover, clean close, or a
        classified failure."""
        iterations = 0
        while True:
            iterations += 1
            if iterations > max_iterations:  # pragma: no cover - safety net
                self._fail("pump", RuntimeError("iteration limit exceeded"))
            try:
                outcome = self._pump_once()
            except ExchangeFailed:
                raise
            if outcome is not None:
                return outcome

    def _pump_once(self) -> Optional[Outcome]:
        assert self._binding is not None

        # 1) Switched connection: h11 is permanently out of the loop.
        if self.is_switched:
            return self._pump_tunnel()

        # 2) Ordinary HTTP parsing.
        try:
            chunk = self._transport.read_some()
        except ReadFailure as exc:
            self._fail("read", exc)
        if chunk is None:
            # No data and no EOF yet: nothing to do; in the offline replay
            # harness this means the scenario stream is exhausted without a
            # terminal event, which we surface as a classified failure.
            self._fail(
                "read",
                ReadFailure("read", "stream exhausted before exchange completed"),
            )
        assert chunk is not None
        eof = chunk == b""
        if not eof:
            self._trace.bytes_received += len(chunk)
            self._trace.record(
                "transport.read",
                states=self._conn.states,
                chunk_len=len(chunk),
            )
            try:
                self._conn.receive_data(chunk)
            except RuntimeError as exc:
                # h11: data after EOF, or other receive-buffer contract error.
                self._fail("receive_data", exc)
        else:
            self._trace.record(
                "transport.eof",
                states=self._conn.states,
                detail={"direction": "peer write side closed"},
            )
            try:
                self._conn.receive_data(b"")
            except RuntimeError as exc:
                self._fail("receive_eof", exc)

        # 3) Drain every event h11 can produce from this read.
        return self._drain_events(eof)

    def _drain_events(self, eof: bool) -> Optional[Outcome]:
        binding = self._binding
        assert binding is not None
        while True:
            try:
                event = self._conn.next_event()
            except h11.RemoteProtocolError as exc:
                self._fail("parse", exc)
            except h11.LocalProtocolError as exc:  # adapter misuse -> defect class
                self._fail("adapter", exc)

            if event is h11.NEED_DATA:
                self._trace.record_sentinel("next_event.need_data", h11.NEED_DATA, self._conn)
                return None
            if event is h11.PAUSED:
                return self._handle_paused(eof)

            assert isinstance(event, h11.Event)
            self._trace.record_event("next_event." + type(event).__name__, event, self._conn)

            if isinstance(event, (h11.Response, h11.InformationalResponse)):
                self._on_response_event(event, binding)
            elif isinstance(event, h11.Data):
                payload = bytes(event.data)
                binding.body_parts.append(payload)
                self._trace.account_http_delivery(payload)
            elif isinstance(event, h11.EndOfMessage):
                binding.response_complete = True
                return self._finish_ordinary(binding)
            elif isinstance(event, h11.ConnectionClosed):
                return self._finish_closed(binding)

    def _on_response_event(
        self, event: h11.Event, binding: _Binding
    ) -> None:
        if isinstance(event, h11.InformationalResponse):
            if event.status_code == 101 and binding.mode == UPGRADE:
                decision = self._policy.review_server_acceptance(
                    binding.context, UPGRADE, binding.target, event
                )
                self._trace.record_decision("policy.review_server_acceptance", decision)
                if decision.denied:
                    # h11 itself would only reach here on a proposed upgrade;
                    # a denied 101 means the application refuses the upgrade
                    # even though the wire offered it. Treat as ordinary
                    # response path is impossible post-101, so fail closed.
                    self._fail(
                        "switch_decision",
                        RuntimeError("101 accepted on wire but denied by policy"),
                    )
                binding.response = event  # informational, terminal for upgrade
            return

        assert isinstance(event, h11.Response)
        binding.response = event
        if binding.mode == CONNECT and 200 <= event.status_code < 300:
            decision = self._policy.review_server_acceptance(
                binding.context, CONNECT, binding.target, event
            )
            self._trace.record_decision("policy.review_server_acceptance", decision)
            if decision.denied:
                self._fail(
                    "switch_decision",
                    RuntimeError("CONNECT 2xx accepted on wire but denied by policy"),
                )
        # Any other status (including CONNECT 4xx/5xx) is an ordinary response.

    def _handle_paused(self, eof: bool) -> Optional[Outcome]:
        binding = self._binding
        assert binding is not None
        self._trace.record_sentinel("next_event.paused", h11.PAUSED, self._conn)
        states = self._conn.states

        # Switched: h11 has handed control to the other protocol.
        if states[h11.CLIENT] is h11.SWITCHED_PROTOCOL:
            return self._perform_handover(eof, binding)

        # MIGHT_SWITCH_PROTOCOL: still waiting to learn accept vs. reject.
        # Bytes buffered here MUST NOT be delivered as business data, and
        # MUST NOT be parsed while the verdict is pending. h11 already keeps
        # them in its receive buffer; we simply wait for more wire bytes.
        if states[h11.CLIENT] is h11.MIGHT_SWITCH_PROTOCOL:  # type: ignore[attr-defined]
            trailing, closed = self._conn.trailing_data
            self._trace.record(
                "might_switch.hold",
                states=states,
                detail={
                    "buffered_but_undelivered": len(trailing),
                    "peer_closed": closed,
                },
            )
            if eof and closed:
                # Peer went away while the switch verdict was pending.
                self._fail(
                    "awaiting_switch",
                    ReadFailure("awaiting_switch", "peer closed during switch negotiation"),
                )
            return None  # need another transport read

        # DONE-with-buffered-data pause (pipelined next request) or similar:
        # not reachable in a single-exchange controller, but handle safely.
        self._fail(
            "paused",
            RuntimeError(f"unexpected PAUSED in states {states}"),
        )
        raise AssertionError("unreachable: _fail always raises")

    def _perform_handover(self, eof: bool, binding: _Binding) -> Outcome:
        if binding.handover_done:
            # Defensive: a second handover attempt would mean double delivery.
            self._fail(
                "handover",
                RuntimeError("duplicate tunnel handover attempted"),
            )
        trailing, closed = self._conn.trailing_data
        # Drain h11's buffer exactly once; from now on bytes go straight to
        # the tunnel sink and never re-enter the parser. We clear the
        # underlying receive buffer so ownership is unambiguous: after the
        # handover h11 holds zero bytes and trailing_data stays empty.
        binding.switched = True
        binding.handover_done = True
        handover = Handover(
            mode=binding.mode or "unknown",
            target=binding.target,
            prefix=bytes(trailing),
            eof_seen=bool(closed or eof),
            produced=True,
        )
        if trailing:
            self._deliver_tunnel(bytes(trailing))
        # The single ownership-transfer event, distinct from chunk delivery.
        self._trace.account_handover_transfer()
        # Ownership transfer: remove every handed-over byte from h11.
        del self._conn._receive_buffer._data[:]  # noqa: SLF001
        assert bytes(self._conn.trailing_data[0]) == b""
        self._tunnel_mode = True
        self._trace.record(
            "tunnel.handover",
            states=self._conn.states,
            detail={
                "mode": handover.mode,
                "target": handover.target,
                "prefix_length": len(handover.prefix),
                "prefix_digest": (
                    byte_digest(handover.prefix) if handover.prefix else None
                ),
                "eof": handover.eof_seen,
            },
            buffer_len=0,
        )
        # Switched connections never return to the pool.
        self._permanently_closed = True
        return Outcome(
            kind="switched",
            response=binding.response,
            handover=handover,
            reusable=False,
        )

    def _pump_tunnel(self) -> Optional[Outcome]:
        # Post-handover reads bypass h11 entirely.
        if self._tunnel_terminal:
            # Idempotent terminal result: repeated pumps never re-deliver or
            # raise spuriously (duplicate-completion-notification safety).
            return Outcome(
                kind="closed" if self._eof_reported else "switched",
                body=self.tunnel_bytes,
                reusable=False,
            )
        try:
            chunk = self._transport.read_some()
        except ReadFailure as exc:
            self._fail("tunnel_read", exc)
        if chunk is None:
            # Offline stream exhausted without EOF: normal replay stop point,
            # not an HTTP failure. Report a stable terminal outcome.
            self._tunnel_terminal = True
            return Outcome(
                kind="switched",
                response=self._binding.response if self._binding else None,
                reusable=False,
            )
        if chunk == b"":
            self._eof_reported = True
            self._tunnel_terminal = True
            self._trace.record(
                "tunnel.eof",
                states=self._conn.states,
                detail={"direction": "peer write side closed"},
            )
            return Outcome(
                kind="closed",
                body=self.tunnel_bytes,
                reusable=False,
            )
        self._trace.bytes_received += len(chunk)
        self._trace.record(
            "tunnel.read",
            states=self._conn.states,
            chunk_len=len(chunk),
        )
        self._deliver_tunnel(chunk)
        return None

    def _deliver_tunnel(self, data: bytes) -> None:
        if not data:
            return
        self._tunnel_bytes.append(data)
        self._trace.account_tunnel_handover(data)
        self._tunnel_sink(data)

    # -- ordinary completion / close --------------------------------------

    def _finish_ordinary(self, binding: _Binding) -> Outcome:
        body = b"".join(binding.body_parts)
        keep_alive = self._conn.states[h11.CLIENT] is h11.DONE
        self._trace.record(
            "exchange.complete",
            states=self._conn.states,
            detail={"body_length": len(body), "keep_alive": keep_alive},
        )
        response = binding.response
        if keep_alive:
            # Both roles must be DONE before the next cycle; h11 enforces it.
            self._conn.start_next_cycle()
            self._trace.record(
                "connection.recycle",
                states=self._conn.states,
                detail={"start_next_cycle": True},
            )
        else:
            self._permanently_closed = True
        # Release every piece of per-exchange state, including the trust
        # context, so it cannot influence the next exchange.
        self._binding = None
        return Outcome(
            kind="complete",
            response=response,
            body=body,
            reusable=keep_alive,
        )

    def _finish_closed(self, binding: _Binding) -> Outcome:
        self._trace.record(
            "connection.closed",
            states=self._conn.states,
            detail={"partial_body_length": sum(map(len, binding.body_parts))},
        )
        self._permanently_closed = True
        self._binding = None
        return Outcome(
            kind="closed",
            response=binding.response,
            body=b"".join(binding.body_parts),
            reusable=False,
        )

    # -- failure handling --------------------------------------------------

    def _fail(self, stage: str, exc: BaseException) -> None:
        """Classify and record a failure, poison the connection and release
        the request binding.  Never silently swallows the error."""
        self._trace.record(
            "exchange.failed",
            states=self._conn.states,
            detail={
                "stage": stage,
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        # Move h11 to ERROR if it is not already there (send_failed handles
        # our-role failures; parse errors already moved their-role).
        try:
            if self._conn.our_state is not h11.ERROR:
                self._conn.send_failed()
        except Exception:  # pragma: no cover - best-effort poisoning
            pass
        self._permanently_closed = True
        binding = self._binding
        # Release cached request/body state and the trusted identity context.
        self._binding = None
        failure = ExchangeFailed(stage, exc)
        if binding is not None:
            self._trace.record(
                "binding.released",
                states=self._conn.states,
                detail={"had_target": binding.target is not None},
            )
        raise failure
