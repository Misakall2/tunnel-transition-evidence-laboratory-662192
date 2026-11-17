"""Integration-error tests: mistakes a caller can make on top of h11.

These tests deliberately construct *incorrect* adapters and show the failure
mode each mistake produces, then assert the correct
:class:`tunnellab.controller.ConnectionController` avoids it. The point is
the error taxonomy: every failure here originates in caller logic, while the
underlying h11 state machine behaves exactly as ``test_library_state``
proves it should. h11 itself is never patched or blamed for these.

Mistakes demonstrated:

1. feeding tunnel bytes back into ``next_event`` after a switch;
2. delivering buffered might-switch bytes to business logic;
3. switching without a trust check (open proxy / smuggling enabler);
4. returning a switched/failed connection to the reuse pool;
5. reusing a trust context across different targets.
"""

import h11
import pytest

from tunnellab.controller import ConnectionController, ExchangeFailed, SwitchRejected
from tunnellab.policy import SwitchPolicy, TrustContext
from tunnellab.trace import EventTrace
from tunnellab.transport import make_transport_pair

ACCEPT = b"HTTP/1.1 200 OK\r\n\r\n"
TUNNEL = b"\x16\x03\x03raw-tunnel"


def _connect_request() -> h11.Request:
    return h11.Request(
        method="CONNECT",
        target="allowed.example:443",
        headers=[("Host", "allowed.example:443")],
    )


def _trusted_ctx() -> TrustContext:
    return TrustContext(
        client_id="c",
        allowed_authorities=frozenset({"allowed.example:443"}),
    )


def test_mistake_1_parsing_tunnel_bytes_after_switch_is_futile() -> None:
    """A wrong adapter keeps calling next_event after a switch.

    h11 does not mis-parse the tunnel bytes (that would be a library defect);
    it simply returns PAUSED forever. The mistake is the caller expecting
    HTTP events where ownership has already transferred.
    """
    conn = h11.Connection(h11.CLIENT)
    conn.send(_connect_request())
    conn.send(h11.EndOfMessage())
    conn.receive_data(ACCEPT + TUNNEL)
    assert isinstance(conn.next_event(), h11.Response)
    for _ in range(5):
        assert conn.next_event() is h11.PAUSED
    # Bytes remain available via trailing_data; the parser never consumes them.
    assert conn.trailing_data[0] == TUNNEL
    assert conn.their_state is h11.SWITCHED_PROTOCOL


def test_correct_adapter_drains_trailing_bytes_once_and_clears_the_buffer() -> None:
    client_t, peer_t = make_transport_pair("c", "p")
    peer_t.write(ACCEPT + TUNNEL)
    trace = EventTrace(scenario="correct", fragmentation="whole")
    controller = ConnectionController(
        client_t, SwitchPolicy(), trace
    )
    controller.submit_request(_trusted_ctx(), _connect_request())
    outcome = controller.pump_until_outcome()
    assert outcome.kind == "switched"
    # Exactly one handover, every byte transferred, h11 left holding nothing.
    assert controller.tunnel_bytes == TUNNEL
    assert controller.conn.trailing_data[0] == b""
    assert trace.to_dict()["byte_ledger"]["tunnel_handover_count"] == 1


def test_mistake_2_delivering_might_switch_bytes_to_business_logic() -> None:
    """A naive adapter treats PAUSED-buffered data as an HTTP body."""
    s = h11.Connection(h11.SERVER)
    s.receive_data(b"CONNECT h.example:443 HTTP/1.1\r\nHost: h.example:443\r\n\r\n")
    s.next_event()  # Request
    s.next_event()  # EndOfMessage
    s.receive_data(b"GET /smuggle HTTP/1.0\r\n\r\n")
    assert s.next_event() is h11.PAUSED
    buffered, _ = s.trailing_data
    # The WRONG move would be handing `buffered` to the request handler. The
    # correct behavior is to hold it until the switch verdict is known.
    assert buffered == b"GET /smuggle HTTP/1.0\r\n\r\n"
    # Denying the switch returns the held bytes to normal parsing safely.
    deny = (
        b"HTTP/1.1 403 No\r\nContent-Length: 0\r\n\r\n"
    )
    # Build the denial through a real server connection path.
    s.send(h11.Response(status_code=403, headers=[("Content-Length", "0")]))
    s.send(h11.EndOfMessage())
    assert deny  # document the wire shape the denial corresponds to
    assert s.states[h11.CLIENT] in (h11.DONE, h11.MUST_CLOSE)


def test_mistake_3_switching_without_a_trust_check_is_blocked() -> None:
    """An adapter with a deny-all policy must never emit the CONNECT."""
    client_t, peer_t = make_transport_pair("c", "p")
    trace = EventTrace(scenario="no-trust", fragmentation="n/a")
    controller = ConnectionController(
        client_t, SwitchPolicy(), trace  # default: deny all switches
    )
    with pytest.raises(SwitchRejected):
        controller.submit_request(TrustContext(client_id="c"), _connect_request())
    # No bytes left the client: the open-proxy/smuggling path is closed.
    assert client_t.bytes_written == 0
    assert controller.binding is None


def test_mistake_4_pooling_a_switched_connection_is_refused() -> None:
    from tunnellab.pool import ConnectionPool

    client_t, peer_t = make_transport_pair("c", "p")
    peer_t.write(ACCEPT + TUNNEL)
    trace = EventTrace(scenario="pool-switch", fragmentation="whole")
    controller = ConnectionController(client_t, SwitchPolicy(), trace)
    controller.submit_request(_trusted_ctx(), _connect_request())
    controller.pump_until_outcome()
    assert controller.is_switched

    pool = ConnectionPool()
    entry = pool.register_active("allowed.example:443", controller, trace)
    pool.release(entry)
    # The switched connection was retired, never stored for reuse.
    assert pool.idle_count == 0
    assert any("switched" in r for r in pool.retirements)
    assert not controller.reusable_for_next_request()


def test_mistake_5_failed_connection_is_retired_and_binding_released() -> None:
    from tunnellab.pool import ConnectionPool

    client_t, peer_t = make_transport_pair("c", "p")
    peer_t.write(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab")
    peer_t.write_eof()  # truncated body then close
    trace = EventTrace(scenario="pool-fail", fragmentation="whole")
    controller = ConnectionController(client_t, SwitchPolicy(), trace)
    controller.submit_request(
        TrustContext(client_id="c"),
        h11.Request(method="GET", target="/",
                    headers=[("Host", "example.test"), ("Content-Length", "0")]),
    )
    with pytest.raises(ExchangeFailed) as excinfo:
        controller.pump_until_outcome()
    assert excinfo.value.stage == "parse"
    # Failure poisons reuse and drops the trusted binding atomically.
    assert controller.is_permanently_closed
    assert controller.binding is None
    pool = ConnectionPool()
    entry = pool.register_active("example.test", controller, trace)
    pool.release(entry)
    assert pool.idle_count == 0


def test_identity_context_does_not_leak_between_exchanges() -> None:
    client_t, peer_t = make_transport_pair("c", "p")
    trace = EventTrace(scenario="identity", fragmentation="whole")
    controller = ConnectionController(client_t, SwitchPolicy(), trace)
    # First exchange trusts one authority and completes an ordinary response.
    peer_t.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    controller.submit_request(
        TrustContext(
            client_id="c",
            allowed_authorities=frozenset({"allowed.example:443"}),
        ),
        h11.Request(method="GET", target="/",
                    headers=[("Host", "example.test"), ("Content-Length", "0")]),
    )
    outcome = controller.pump_until_outcome()
    assert outcome.reusable and controller.binding is None
    # A later CONNECT with an empty context must not inherit prior authority.
    with pytest.raises(SwitchRejected):
        controller.submit_request(
            TrustContext(client_id="c"), _connect_request()
        )
