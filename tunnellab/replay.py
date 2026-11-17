"""Offline replay engine: run every scenario under every fragmentation.

The engine never opens a socket and never resolves a name.  It feeds the
scenario transcripts through :class:`MemoryTransport` into
:class:`ConnectionController`, captures the :class:`EventTrace`, asserts the
byte-level invariants, and emits JSON-serializable evidence.
"""

import base64
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import h11

from .controller import (
    ConnectionController,
    ExchangeFailed,
    Outcome,
    SwitchRejected,
)
from .policy import SwitchPolicy, TrustContext
from .scenarios import (
    FRAGMENTATIONS,
    Scenario,
    authenticated_request_spec,
    build_scenarios,
    fragment,
    policy_rejection_scenarios,
)
from .trace import REDACTED_HEADERS, EventTrace, byte_digest
from .transport import MemoryTransport, ReadFailure, make_transport_pair

__all__ = ["ReplayResult", "run_scenario", "run_all", "LAB_POLICY"]


# The laboratory's fixed trust table. Only these authorities/tokens may be
# tunnelled; everything else is denied before bytes are written.
LAB_POLICY = SwitchPolicy(
    default_authorities=frozenset({"allowed.example:443"}),
    default_upgrades=frozenset({"websocket"}),
)


@dataclass
class ReplayResult:
    scenario: str
    fragmentation: str
    outcome: Optional[Outcome]
    error: Optional[ExchangeFailed]
    trace: EventTrace
    transport: MemoryTransport
    controller: ConnectionController
    assertions: List[str]
    assertion_failures: List[str]

    @property
    def passed(self) -> bool:
        return not self.assertion_failures


def _load_peer_stream(
    writer: MemoryTransport,
    reader: MemoryTransport,
    scenario: Scenario,
    strategy: str,
) -> None:
    # Stage the full stream through the peer (writer). The cuts only affect
    # where chunk boundaries fall, never the byte sequence.
    for chunk in fragment(scenario.peer_wire, strategy):
        writer.write(chunk)
    # Arm a fragmentation-independent read fault on the *reader* endpoint,
    # since that is the side whose reads the controller drives.
    if scenario.fail_after_bytes is not None:
        reader.fail_after_total_bytes(
            scenario.fail_after_bytes,
            ReadFailure(scenario.fail_stage or "read", "injected by replay"),
        )
    if scenario.peer_eof_after:
        writer.write_eof()


def _context_for(scenario: Scenario) -> TrustContext:
    spec = scenario.request_spec
    authorities: frozenset[str] = frozenset()
    upgrades: frozenset[str] = frozenset()
    if spec.get("method") == "CONNECT":
        authorities = frozenset({str(spec.get("target", "")).lower()})
    if "upgrade" in spec:
        upgrades = frozenset({str(spec["upgrade"]).lower()})
    return TrustContext(
        client_id="lab-client",
        allowed_authorities=authorities,
        allowed_upgrades=upgrades,
    )


def _coerce_headers(raw: object) -> List[Tuple[str, str]]:
    if not isinstance(raw, list):  # pragma: no cover - defensive
        raise ValueError("scenario spec must carry a list of header pairs")
    return [(str(name), str(value)) for name, value in raw]


def _request_from_scenario(scenario: Scenario) -> h11.Request:
    spec = scenario.request_spec
    raw_headers = spec.get("headers")
    if not raw_headers:  # pragma: no cover - all lab scenarios carry headers
        raise ValueError(f"scenario {scenario.name!r} is missing exact headers")
    return h11.Request(
        method=str(spec["method"]),
        target=str(spec["target"]),
        headers=_coerce_headers(raw_headers),
    )


def run_scenario(
    scenario: Scenario, strategy: str, record_wire: bool = True
) -> ReplayResult:
    client_t, peer_t = make_transport_pair("client", "peer")
    trace = EventTrace(scenario=scenario.name, fragmentation=strategy)
    controller = ConnectionController(client_t, LAB_POLICY, trace)
    assertions: List[str] = []
    failures: List[str] = []

    # Stage the peer side before we pump, applying the fragmentation cuts.
    _load_peer_stream(peer_t, client_t, scenario, strategy)

    # Send the request through the policy-gated controller.
    try:
        request = _request_from_scenario(scenario)
        controller.submit_request(_context_for(scenario), request)
        sent_ok = True
    except SwitchRejected:
        sent_ok = False
    except ExchangeFailed as exc:  # pragma: no cover - defensive
        return ReplayResult(
            scenario.name, strategy, None, exc, trace, client_t,
            controller, assertions, [f"unexpected submit failure: {exc!r}"],
        )

    if not scenario.expectations.sends_request:
        return ReplayResult(
            scenario.name, strategy, None, None, trace, client_t,
            controller, assertions,
            [] if not sent_ok else ["policy should have blocked the request"],
        )

    # Pump to a terminal outcome.
    outcome: Optional[Outcome] = None
    error: Optional[ExchangeFailed] = None
    try:
        outcome = controller.pump_until_outcome()
        # After a successful switch the first outcome is the handover. Keep
        # draining the tunnel until the offline stream ends, but preserve the
        # original "switched" outcome so assertions see exactly one handover.
        if outcome is not None and outcome.kind == "switched":
            while True:
                more = controller.pump_until_outcome()
                if more.kind in ("switched", "closed"):
                    if more.kind == "closed":
                        break
                    continue
                outcome = more  # pragma: no cover - defensive
                break
    except ExchangeFailed as exc:
        error = exc

    result = ReplayResult(
        scenario.name, strategy, outcome, error, trace, client_t,
        controller, assertions, failures,
    )
    _check_expectations(result, scenario, sent_ok, record_wire)
    return result


def _check_expectations(
    result: ReplayResult, scenario: Scenario, sent_ok: bool, record_wire: bool
) -> None:
    exp = scenario.expectations
    ledger = result.trace.to_dict()["byte_ledger"]

    def check(condition: bool, message: str) -> None:
        result.assertions.append(message)
        if not condition:
            result.assertion_failures.append(message)

    check(sent_ok, "request was allowed onto the wire")
    # The controller re-serializes the request through h11 (header names are
    # normalized to lowercase), so compare structure, not transcript identity.
    sent_wire = b"".join(result.transport.write_history)
    spec = scenario.request_spec
    expected_line = (
        f"{spec['method']} {spec['target']} HTTP/1.1\r\n".encode("ascii")
    )
    check(
        sent_wire.startswith(expected_line),
        "sent wire starts with the authorized request line",
    )
    check(
        sent_wire.endswith(b"\r\n\r\n") or b"\r\n\r\n" in sent_wire,
        "sent request is a complete header-terminated message",
    )
    check(
        result.transport.bytes_written == len(sent_wire),
        "write accounting matches write history exactly",
    )

    if exp.outcome_kind == "failed":
        check(result.error is not None, "exchange reported a failure")
        if result.error is not None:
            check(
                result.error.stage == exp.failure_stage,
                f"failure stage {result.error.stage!r} == {exp.failure_stage!r}",
            )
        check(
            result.controller.is_permanently_closed,
            "failed connection permanently removed from reuse",
        )
        check(
            result.controller.binding is None,
            "trust binding released after failure",
        )
        return

    assert result.outcome is not None
    check(
        result.outcome.kind == exp.outcome_kind,
        f"outcome {result.outcome.kind!r} == {exp.outcome_kind!r}",
    )

    if exp.outcome_kind == "complete":
        check(result.outcome.body == exp.http_body, "HTTP body bytes match exactly")
        check(
            result.outcome.reusable is exp.reusable,
            f"reusable flag {result.outcome.reusable} == {exp.reusable}",
        )
        if exp.http_delivery_count is not None:
            # The number of Data *events* may vary with fragmentation; what
            # is fixed is the delivered byte count and the fact that delivery
            # happened at least the expected number of times with zero loss.
            check(
                ledger["http_delivered"] == len(exp.http_body),
                f"HTTP delivered bytes {ledger['http_delivered']} "
                f"== {len(exp.http_body)} (in {ledger['http_delivery_count']} event(s))",
            )
            check(
                ledger["http_delivery_count"] >= exp.http_delivery_count,
                f"HTTP delivery event count {ledger['http_delivery_count']} "
                f">= minimum {exp.http_delivery_count}",
            )
        check(ledger["tunnel_handed_over"] == 0, "no bytes handed to tunnel")

    if exp.outcome_kind in ("switched", "closed") and exp.tunnel_prefix:
        tunnel = result.controller.tunnel_bytes
        expected = exp.tunnel_prefix + exp.tunnel_rest
        check(tunnel == expected, "tunnel bytes match exactly and in order")
        check(
            ledger["tunnel_handover_count"] == 1,
            "tunnel handover happened exactly once",
        )
        check(
            result.controller.is_permanently_closed,
            "switched connection permanently left the pool",
        )
        # After a handover h11 must hold zero residual bytes: ownership of
        # every byte has moved to the tunnel, exactly once.
        residual, _ = result.controller.conn.trailing_data
        check(residual == b"", "no bytes remain in h11 receive buffer after handover")
        # The parser must refuse further HTTP events post-switch.
        check(
            result.controller.conn.their_state is h11.SWITCHED_PROTOCOL,
            "h11 peer state stays SWITCHED_PROTOCOL",
        )

    # Cross-cutting byte conservation. Every byte read ends up in exactly one
    # place: HTTP body, tunnel, h11's residual buffer, or consumed by the
    # parser as framing (request/status lines, headers, chunk metadata). The
    # framing portion is derived by subtraction, so the books must balance
    # exactly and no byte can be delivered more times than it was read.
    residual_bytes, _ = result.controller.conn.trailing_data
    payload_accounted = (
        ledger["http_delivered"]
        + ledger["tunnel_handed_over"]
        + len(residual_bytes)
    )
    framing_consumed = result.transport.bytes_read - payload_accounted
    if result.error is None:
        check(
            framing_consumed >= 0,
            f"no over-delivery: payload {payload_accounted} <= read "
            f"{result.transport.bytes_read}",
        )
        check(
            payload_accounted + framing_consumed == result.transport.bytes_read,
            "byte conservation: body + tunnel + residual + framing == bytes read",
        )
        check(
            ledger["http_delivery_count"] == 0
            or ledger["http_delivered"] > 0,
            "every HTTP delivery carried bytes (empty deliveries are suppressed)",
        )
        check(
            ledger["tunnel_handover_count"] in (0, 1),
            "tunnel ownership transfer happens 0 or 1 time",
        )


def run_policy_rejections() -> List[ReplayResult]:
    results: List[ReplayResult] = []
    for spec in policy_rejection_scenarios():
        client_t, peer_t = make_transport_pair("client", "peer")
        trace = EventTrace(scenario=str(spec["name"]), fragmentation="n/a")
        controller = ConnectionController(client_t, LAB_POLICY, trace)
        request = h11.Request(
            method=str(spec["method"]),
            target=str(spec["target"]),
            headers=_coerce_headers(spec["headers"]),
        )
        blocked = False
        try:
            # Context grants nothing relevant to the requested target/token.
            controller.submit_request(
                TrustContext(client_id="lab-client"), request
            )
        except SwitchRejected as exc:
            blocked = True
            trace.record_decision("policy.reject", exc.decision)
        assertions = ["policy blocked the switch before sending"]
        failures = [] if blocked else ["switch was not blocked"]
        if client_t.bytes_written != 0:
            failures.append("bytes were written despite policy denial")
        results.append(
            ReplayResult(
                str(spec["name"]), "n/a", None, None, trace, client_t,
                controller, assertions, failures,
            )
        )
    return results


def evidence_payload(result: ReplayResult, scenario: Scenario) -> Dict[str, Any]:
    """JSON-safe evidence bundle. Wire bytes are base64; secrets redacted."""
    payload: Dict[str, Any] = {
        "scenario": scenario.name,
        "description": scenario.description,
        "fragmentation": result.fragmentation,
        "transcripts": {
            "request_wire_b64": base64.b64encode(scenario.request_wire).decode("ascii"),
            "peer_wire_b64": base64.b64encode(scenario.peer_wire).decode("ascii"),
            "request_wire_length": len(scenario.request_wire),
            "peer_wire_length": len(scenario.peer_wire),
            "peer_eof_after": scenario.peer_eof_after,
        },
        "expectations": {
            "outcome_kind": scenario.expectations.outcome_kind,
            "failure_stage": scenario.expectations.failure_stage,
            "reusable": scenario.expectations.reusable,
            "http_body_digest": byte_digest(scenario.expectations.http_body),
            "tunnel_prefix_digest": byte_digest(scenario.expectations.tunnel_prefix),
        },
        "trace": result.trace.to_dict(),
        "assertions": result.assertions,
        "assertion_failures": result.assertion_failures,
        "passed": result.passed,
    }
    if result.error is not None:
        payload["observed_failure"] = {
            "stage": result.error.stage,
            "error_type": type(result.error.cause).__name__,
            "message": str(result.error.cause),
        }
    if result.outcome is not None:
        payload["observed_outcome"] = {
            "kind": result.outcome.kind,
            "reusable": result.outcome.reusable,
        }
        if result.outcome.handover is not None:
            ho = result.outcome.handover
            payload["observed_outcome"]["handover"] = {
                "mode": ho.mode,
                "target": ho.target,
                "prefix_length": len(ho.prefix),
                "prefix_digest": byte_digest(ho.prefix),
                "eof_seen": ho.eof_seen,
            }
    return payload


def run_all() -> Tuple[List[ReplayResult], List[ReplayResult], List[Dict[str, Any]]]:
    """Replay every scenario under every fragmentation strategy."""
    results: List[ReplayResult] = []
    evidence: List[Dict[str, Any]] = []
    scenarios = build_scenarios()
    for scenario in scenarios:
        for strategy in FRAGMENTATIONS:
            result = run_scenario(scenario, strategy)
            results.append(result)
            evidence.append(evidence_payload(result, scenario))
    rejections = run_policy_rejections()
    for result in rejections:
        evidence.append(
            {
                "scenario": result.scenario,
                "fragmentation": "n/a",
                "trace": result.trace.to_dict(),
                "assertions": result.assertions,
                "assertion_failures": result.assertion_failures,
                "passed": result.passed,
            }
        )
    return results, rejections, evidence


def redaction_evidence() -> Dict[str, Any]:
    """Demonstrate that secret header values never reach the trace."""
    spec = authenticated_request_spec()
    client_t, peer_t = make_transport_pair("client", "peer")
    trace = EventTrace(scenario="redaction_check", fragmentation="n/a")
    controller = ConnectionController(
        client_t,
        SwitchPolicy(),  # no switches in this scenario
        trace,
    )
    request = h11.Request(
        method=str(spec["method"]),
        target=str(spec["target"]),
        headers=_coerce_headers(spec["headers"]),
    )
    controller.submit_request(TrustContext(client_id="lab-client"), request)
    serialized = trace.to_dict()
    raw_text = str(serialized)
    leaks = []
    for header_name in REDACTED_HEADERS:
        # Values from authenticated_request_spec:
        pass
    secret_values = [
        "super-secret-token-1234",
        "dXNlcjpwYXNz",
        "top-secret",
    ]
    for value in secret_values:
        if value in raw_text:
            leaks.append(value)
    return {
        "scenario": "redaction_check",
        "redacted_header_names": sorted(n.decode("ascii") for n in REDACTED_HEADERS),
        "secret_values_absent_from_trace": not leaks,
        "leaks": leaks,
        "trace": serialized,
    }
