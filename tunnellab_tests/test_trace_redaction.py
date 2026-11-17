"""Evidence and redaction tests.

Diagnostic traces must correlate events, states, buffer ownership and
decisions while never containing authentication header values or tunnel
payloads in the clear.
"""

import json

import h11

from tunnellab.controller import ConnectionController
from tunnellab.policy import SwitchPolicy, TrustContext
from tunnellab.replay import redaction_evidence, run_all
from tunnellab.trace import (
    REDACTED_HEADERS,
    EventTrace,
    byte_digest,
    describe_event,
    redact_headers,
)
from tunnellab.transport import make_transport_pair

SECRET_HEADER_VALUES = [
    "super-secret-token-1234",
    "dXNlcjpwYXNz",
    "top-secret",
]


def test_sensitive_headers_are_redacted_but_others_kept() -> None:
    request = h11.Request(
        method="GET",
        target="/private",
        headers=[
            ("Host", "example.test"),
            ("Authorization", "Bearer super-secret-token-1234"),
            ("Proxy-Authorization", "Basic dXNlcjpwYXNz"),
            ("Cookie", "session=top-secret"),
            ("X-Trace", "non-secret"),
        ],
    )
    redacted = dict(redact_headers(request.headers))
    for name in ("authorization", "proxy-authorization", "cookie"):
        assert redacted[name] == "<redacted>"
    assert redacted["x-trace"] == "non-secret"
    # The description never embeds raw secret material.
    blob = json.dumps(describe_event(request))
    for secret in SECRET_HEADER_VALUES:
        assert secret not in blob


def test_data_events_record_length_and_digest_not_payload() -> None:
    payload = b"sensitive-payload-bytes"
    event = h11.Data(data=payload)
    described = describe_event(event)
    assert described == {
        "kind": "Data",
        "length": len(payload),
        "digest": byte_digest(payload),
    }
    assert payload.decode("ascii") not in json.dumps(described)


def test_full_trace_contains_no_secret_values() -> None:
    evidence = redaction_evidence()
    assert evidence["secret_values_absent_from_trace"] is True
    assert evidence["leaks"] == []
    blob = json.dumps(evidence)
    for secret in SECRET_HEADER_VALUES:
        assert secret not in blob


def test_trace_correlates_event_state_and_buffer_ownership() -> None:
    client_t, peer_t = make_transport_pair("c", "p")
    peer_t.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    trace = EventTrace(scenario="corr", fragmentation="whole")
    controller = ConnectionController(client_t, SwitchPolicy(), trace)
    controller.submit_request(
        TrustContext(client_id="c"),
        h11.Request(method="GET", target="/",
                    headers=[("Host", "example.test"), ("Content-Length", "0")]),
    )
    controller.pump_until_outcome()
    steps = [e["step"] for e in trace.entries]
    # The four evidence dimensions all appear.
    assert any(s.startswith("send.") for s in steps)
    assert any(s.startswith("next_event.") for s in steps)
    assert any("states" in e for e in trace.entries)
    assert any("h11_receive_buffer_bytes" in e for e in trace.entries)
    # A state-bearing entry records both role states by name.
    state_entries = [e for e in trace.entries if "states" in e]
    assert all({"CLIENT", "SERVER"} <= set(e["states"]) for e in state_entries)


def test_evidence_json_is_serializable_and_well_formed() -> None:
    results, rejections, evidence = run_all()
    encoded = json.dumps(evidence)  # must not raise
    decoded = json.loads(encoded)
    assert len(decoded) == len(evidence)
    # Every run carries a trace and a pass/fail verdict.
    for run in decoded:
        assert "trace" in run and "passed" in run
    # Policy rejection evidence records the block and zero failures.
    for rejection in decoded:
        if "policy_rejects" in rejection["scenario"]:
            assert rejection["passed"] is True


def test_tunnel_payload_only_appears_as_digest_and_length() -> None:
    results, _, _ = run_all()
    switched = [
        r for r in results
        if r.outcome and r.outcome.kind == "switched"
    ]
    assert switched, "expected at least one switched run"
    # At least one fragmentation delivers a non-empty prefix inside the same
    # read as the switch response; these carry a digest, never the literal.
    with_prefix = [
        r for r in switched
        if any(
            e["step"] == "tunnel.handover" and e["detail"]["prefix_length"] > 0
            for e in r.trace.entries
        )
    ]
    assert with_prefix, "expected a handover with a non-empty same-read prefix"
    for result in switched:
        blob = json.dumps(result.trace.to_dict())
        # The synthetic tunnel literals must never appear verbatim in traces.
        assert "raw-tunnel-bytes" not in blob
        assert "websocket-frame" not in blob
        # Every handover records the prefix length and (when non-empty) a
        # digest instead of the bytes.
        for entry in result.trace.entries:
            if entry["step"] != "tunnel.handover":
                continue
            detail = entry["detail"]
            assert "prefix_length" in detail
            if detail["prefix_length"] > 0:
                assert detail["prefix_digest"]


def test_redacted_header_set_covers_authentication_headers() -> None:
    expected = {
        b"authorization",
        b"proxy-authorization",
        b"cookie",
        b"set-cookie",
        b"www-authenticate",
        b"proxy-authenticate",
    }
    assert expected <= REDACTED_HEADERS
