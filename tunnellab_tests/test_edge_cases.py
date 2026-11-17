"""Edge-case tests for empty reads, late data and repeated notifications.

These target the specific failure modes where a careless adapter can lose
bytes or deliver them twice. The transport and controller must make every
one of these a no-loss, no-duplicate, explicitly-classified outcome.
"""

import h11
import pytest

from tunnellab.controller import ConnectionController, ExchangeFailed
from tunnellab.policy import SwitchPolicy, TrustContext
from tunnellab.trace import EventTrace
from tunnellab.transport import ReadFailure, make_transport_pair


def _get_request() -> h11.Request:
    return h11.Request(
        method="GET",
        target="/",
        headers=[("Host", "example.test"), ("Content-Length", "0")],
    )


def test_empty_read_before_data_does_not_consume_or_lose_bytes() -> None:
    a, b = make_transport_pair("a", "b")
    # No data and no EOF yet: None, repeatedly.
    for _ in range(3):
        assert b.read_some() is None
    a.write(b"later")
    # The late-arriving data is delivered intact, exactly once.
    assert b.read_some() == b"later"
    assert b.bytes_read == 5


def test_repeated_eof_notifications_are_idempotent() -> None:
    a, b = make_transport_pair("a", "b")
    a.write_eof()
    for _ in range(4):
        assert b.read_some() == b""
    assert b.bytes_read == 0


def test_data_arriving_after_eof_is_refused_not_silently_merged() -> None:
    a, b = make_transport_pair("a", "b")
    a.write_eof()
    assert b.read_some() == b""
    with pytest.raises(Exception):
        # The writer side is closed; a further write is a contract violation.
        a.write(b"resurrected")


def test_repeated_post_handover_pump_never_duplicates_tunnel_bytes() -> None:
    client_t, peer_t = make_transport_pair("c", "p")
    prefix = b"\x16\x03\x03tunnel"
    peer_t.write(b"HTTP/1.1 200 OK\r\n\r\n" + prefix)
    peer_t.write_eof()
    trace = EventTrace(scenario="repeat", fragmentation="whole")
    controller = ConnectionController(client_t, SwitchPolicy(), trace)
    controller.submit_request(
        TrustContext(
            client_id="c",
            allowed_authorities=frozenset({"allowed.example:443"}),
        ),
        h11.Request(
            method="CONNECT",
            target="allowed.example:443",
            headers=[("Host", "allowed.example:443")],
        ),
    )
    first = controller.pump_until_outcome()
    assert first.kind == "switched"
    # Pump many more times: terminal results must not re-deliver bytes.
    for _ in range(5):
        again = controller.pump_until_outcome()
        assert again.kind in ("switched", "closed")
    assert controller.tunnel_bytes == prefix  # exactly one copy
    ledger = trace.to_dict()["byte_ledger"]
    assert ledger["tunnel_handover_count"] == 1


def test_late_data_after_normal_response_is_buffered_not_dropped() -> None:
    # Two responses arrive back-to-back; the second is "late" relative to the
    # first exchange's completion and must survive intact inside h11.
    client_t, peer_t = make_transport_pair("c", "p")
    peer_t.write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond"
    )
    trace = EventTrace(scenario="late", fragmentation="whole")
    controller = ConnectionController(client_t, SwitchPolicy(), trace)
    controller.submit_request(TrustContext(client_id="c"), _get_request())
    outcome = controller.pump_until_outcome()
    assert outcome.body == b"ok"
    residual, _ = controller.conn.trailing_data
    assert residual == b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond"
    # Nothing was delivered twice.
    ledger = trace.to_dict()["byte_ledger"]
    assert ledger["http_delivered"] == 2


def test_read_failure_does_not_partially_deliver_the_faulting_chunk() -> None:
    client_t, peer_t = make_transport_pair("c", "p")
    # Headers plus a 10-byte body; inject the fault after 40 bytes read.
    peer_t.write(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789")
    client_t.fail_after_total_bytes(40, ReadFailure("read", "cut"))
    trace = EventTrace(scenario="fault", fragmentation="whole")
    controller = ConnectionController(client_t, SwitchPolicy(), trace)
    controller.submit_request(TrustContext(client_id="c"), _get_request())
    with pytest.raises(ExchangeFailed) as excinfo:
        controller.pump_until_outcome()
    assert excinfo.value.stage == "read"
    # The connection is poisoned; the binding is released; reuse is impossible.
    assert controller.is_permanently_closed
    assert controller.binding is None
    assert not controller.reusable_for_next_request()


def test_second_request_cannot_start_before_first_exchange_completes() -> None:
    # While an exchange is in flight, a second submit is rejected without
    # disturbing the healthy in-flight binding or writing any extra bytes.
    client_t, peer_t = make_transport_pair("c", "p")
    peer_t.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    trace = EventTrace(scenario="ordering", fragmentation="whole")
    controller = ConnectionController(client_t, SwitchPolicy(), trace)
    controller.submit_request(TrustContext(client_id="c"), _get_request())
    written_before = client_t.bytes_written
    with pytest.raises(ExchangeFailed) as excinfo:
        controller.submit_request(TrustContext(client_id="c"), _get_request())
    assert excinfo.value.stage == "submit"
    # No extra bytes were written and the original exchange still completes.
    assert client_t.bytes_written == written_before
    outcome = controller.pump_until_outcome()
    assert outcome.reusable and controller.binding is None
    # Only after completion (binding released, h11 recycled) may we submit.
    controller.submit_request(TrustContext(client_id="c"), _get_request())
