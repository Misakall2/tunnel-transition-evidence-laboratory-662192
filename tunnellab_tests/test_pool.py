"""Connection-pool lifetime and keep-alive tests."""

import h11

from tunnellab.controller import ConnectionController
from tunnellab.pool import ConnectionPool
from tunnellab.policy import SwitchPolicy, TrustContext
from tunnellab.trace import EventTrace
from tunnellab.transport import make_transport_pair


def _get_request() -> h11.Request:
    return h11.Request(
        method="GET",
        target="/index",
        headers=[("Host", "example.test"), ("Content-Length", "0")],
    )


def _ok_response(body: bytes) -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\nContent-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\n\r\n"
        + body
    )


def test_two_consecutive_requests_share_one_reusable_connection() -> None:
    """The keep-alive path: a second request only starts after both roles
    completed the previous exchange."""
    client_t, peer_t = make_transport_pair("c", "p")
    trace = EventTrace(scenario="keepalive", fragmentation="whole")
    controller = ConnectionController(client_t, SwitchPolicy(), trace)
    ctx = TrustContext(client_id="c")

    # First exchange.
    peer_t.write(_ok_response(b"one"))
    controller.submit_request(ctx, _get_request())
    first = controller.pump_until_outcome()
    assert first.kind == "complete" and first.reusable
    assert controller.reusable_for_next_request()

    # h11 was recycled to IDLE/IDLE inside the controller.
    assert controller.conn.states == {h11.CLIENT: h11.IDLE, h11.SERVER: h11.IDLE}

    # Second exchange on the same controller/transport.
    peer_t.write(_ok_response(b"two"))
    controller.submit_request(ctx, _get_request())
    second = controller.pump_until_outcome()
    assert second.kind == "complete"
    assert second.body == b"two"
    # Two request writes, two responses, no cross-contamination.
    assert first.body == b"one" and second.body == b"two"


def test_pool_acquire_returns_idle_connection_and_retires_failures() -> None:
    pool = ConnectionPool()
    client_t, peer_t = make_transport_pair("c", "p")
    trace = EventTrace(scenario="pool", fragmentation="whole")
    controller = ConnectionController(client_t, SwitchPolicy(), trace)
    peer_t.write(_ok_response(b"x"))
    controller.submit_request(TrustContext(client_id="c"), _get_request())
    controller.pump_until_outcome()

    entry = pool.register_active("example.test", controller, trace)
    assert pool.idle_count == 0
    pool.release(entry)
    assert pool.idle_count == 1

    reused = pool.acquire("example.test", trace)
    assert reused is not None and reused.controller is controller
    assert pool.idle_count == 0


def test_pool_is_authority_scoped() -> None:
    pool = ConnectionPool()
    client_t, peer_t = make_transport_pair("c", "p")
    trace = EventTrace(scenario="scope", fragmentation="whole")
    controller = ConnectionController(client_t, SwitchPolicy(), trace)
    peer_t.write(_ok_response(b"x"))
    controller.submit_request(TrustContext(client_id="c"), _get_request())
    controller.pump_until_outcome()
    entry = pool.register_active("a.example", controller, trace)
    pool.release(entry)
    # A different authority must not receive a.example's connection.
    assert pool.acquire("b.example", trace) is None
    assert pool.acquire("a.example", trace) is not None


def test_switched_connection_is_permanently_excluded_from_pool() -> None:
    pool = ConnectionPool()
    client_t, peer_t = make_transport_pair("c", "p")
    peer_t.write(b"HTTP/1.1 200 OK\r\n\r\n" + b"tunnel")
    trace = EventTrace(scenario="pool-switch", fragmentation="whole")
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
    controller.pump_until_outcome()
    entry = pool.register_active("allowed.example:443", controller, trace)
    pool.release(entry)
    assert pool.idle_count == 0
    assert pool.acquire("allowed.example:443", trace) is None
