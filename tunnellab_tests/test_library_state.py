"""Ground-truth tests for the h11 library itself.

Every assertion here drives a raw :class:`h11.Connection` with in-memory
bytes and records the *actual* state transitions h11 performs. This is the
reference the integration adapter in ``tunnellab.controller`` is built on,
and the evidence used to separate library defects from integration errors
(see ``test_integration_errors.py``).

Nothing here opens a socket. The states asserted are the real, observed
behavior of the vendored h11, not assumptions from the documentation.
"""

import h11
import pytest

from h11._state import _SWITCH_CONNECT, _SWITCH_UPGRADE


def _client_request(method="GET", target="/", headers=None, upgrade=False):
    conn = h11.Connection(h11.CLIENT)
    hdrs = headers if headers is not None else [("Host", "example.test")]
    conn.send(h11.Request(method=method, target=target, headers=hdrs))
    conn.send(h11.EndOfMessage())
    return conn


def test_ordinary_exchange_states_and_reuse() -> None:
    c = _client_request()
    assert c.states == {h11.CLIENT: h11.DONE, h11.SERVER: h11.SEND_RESPONSE}
    c.receive_data(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    )
    events = []
    for _ in range(10):
        e = c.next_event()
        if e in (h11.NEED_DATA, h11.PAUSED):
            break
        events.append(e)
    assert [type(e) for e in events] == [h11.Response, h11.Data, h11.EndOfMessage]
    assert bytes(events[1].data) == b"hello"
    # Both roles DONE: the connection is reusable only after start_next_cycle.
    assert c.states == {h11.CLIENT: h11.DONE, h11.SERVER: h11.DONE}
    c.start_next_cycle()
    assert c.states == {h11.CLIENT: h11.IDLE, h11.SERVER: h11.IDLE}


def test_head_response_delivers_no_body_even_with_content_length() -> None:
    c = _client_request(method="HEAD", target="/r")
    c.receive_data(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n")
    kinds = []
    for _ in range(10):
        e = c.next_event()
        if e in (h11.NEED_DATA, h11.PAUSED):
            break
        kinds.append(type(e))
    # The library knows HEAD has no body: Response then EndOfMessage, no Data.
    assert kinds == [h11.Response, h11.EndOfMessage]
    assert c.states == {h11.CLIENT: h11.DONE, h11.SERVER: h11.DONE}


def test_connect_proposal_enters_might_switch_then_switched() -> None:
    c = _client_request(method="CONNECT", target="h.example:443",
                        headers=[("Host", "h.example:443")])
    # After the request completes the client waits for the switch verdict.
    assert c.states[h11.CLIENT] is h11.MIGHT_SWITCH_PROTOCOL
    c.receive_data(b"HTTP/1.1 200 OK\r\n\r\n")
    response = c.next_event()
    assert isinstance(response, h11.Response)
    assert c.next_event() is h11.PAUSED
    assert c.states == {h11.CLIENT: h11.SWITCHED_PROTOCOL,
                        h11.SERVER: h11.SWITCHED_PROTOCOL}


def test_tunnel_prefix_is_held_in_trailing_data_not_parsed() -> None:
    c = _client_request(method="CONNECT", target="h.example:443",
                        headers=[("Host", "h.example:443")])
    prefix = b"\x16\x03\x03tunnel-bytes"
    c.receive_data(b"HTTP/1.1 200 OK\r\n\r\n" + prefix)
    assert isinstance(c.next_event(), h11.Response)
    assert c.next_event() is h11.PAUSED
    # The library preserves every post-switch byte verbatim and stops parsing.
    trailing, closed = c.trailing_data
    assert trailing == prefix and closed is False
    assert c.next_event() is h11.PAUSED  # still never parses the tunnel


def test_denied_connect_returns_to_normal_http_and_is_reusable() -> None:
    c = _client_request(method="CONNECT", target="h.example:443",
                        headers=[("Host", "h.example:443")])
    assert c.states[h11.CLIENT] is h11.MIGHT_SWITCH_PROTOCOL
    c.receive_data(
        b"HTTP/1.1 403 No\r\nContent-Length: 2\r\n\r\nno"
    )
    kinds = []
    for _ in range(10):
        e = c.next_event()
        if e in (h11.NEED_DATA, h11.PAUSED):
            break
        kinds.append(type(e))
    assert kinds == [h11.Response, h11.Data, h11.EndOfMessage]
    # A rejected switch clears the proposal and returns to DONE/DONE.
    assert c.states == {h11.CLIENT: h11.DONE, h11.SERVER: h11.DONE}
    c.start_next_cycle()
    assert c.states[h11.CLIENT] is h11.IDLE


def test_upgrade_101_switches_and_holds_trailing_bytes() -> None:
    c = _client_request(
        headers=[
            ("Host", "example.test"),
            ("Connection", "Upgrade"),
            ("Upgrade", "websocket"),
        ]
    )
    c.receive_data(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
        b"ws-frame"
    )
    event = c.next_event()
    assert isinstance(event, h11.InformationalResponse)
    assert event.status_code == 101
    assert c.next_event() is h11.PAUSED
    assert c.states[h11.CLIENT] is h11.SWITCHED_PROTOCOL
    assert c.trailing_data[0] == b"ws-frame"


def test_unsolicited_101_is_a_library_protocol_error_not_smuggling() -> None:
    # No Upgrade header was sent, yet the server returns 101. The library's
    # state machine rejects the inconsistent switch itself.
    c = _client_request()
    c.receive_data(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
    )
    with pytest.raises(h11.RemoteProtocolError):
        c.next_event()
    # The peer role is ERROR and the connection must not be reused.
    assert c.states[h11.SERVER] is h11.ERROR
    assert c.their_state is h11.ERROR


def test_unsolicited_connect_acceptance_is_rejected_by_state_machine() -> None:
    from h11._state import ConnectionState
    cs = ConnectionState()
    # Server tries a CONNECT switch with no client proposal -> LocalProtocolError.
    with pytest.raises(h11.LocalProtocolError):
        cs.process_event(h11.SERVER, h11.Response, _SWITCH_CONNECT)
    # An upgrade switch is equally rejected without a proposal.
    with pytest.raises(h11.LocalProtocolError):
        cs.process_event(h11.SERVER, h11.InformationalResponse, _SWITCH_UPGRADE)


def test_switched_connection_can_never_start_a_new_cycle() -> None:
    c = _client_request(method="CONNECT", target="h.example:443",
                        headers=[("Host", "h.example:443")])
    c.receive_data(b"HTTP/1.1 200 OK\r\n\r\n")
    c.next_event()
    assert c.states[h11.CLIENT] is h11.SWITCHED_PROTOCOL
    with pytest.raises(h11.LocalProtocolError):
        c.start_next_cycle()


def test_library_refuses_end_of_message_after_accepted_switch() -> None:
    # On the server role, once CONNECT is accepted there is no HTTP body;
    # emitting EndOfMessage is a state-machine violation the library catches.
    s = h11.Connection(h11.SERVER)
    req_wire = (
        b"CONNECT h.example:443 HTTP/1.1\r\nHost: h.example:443\r\n\r\n"
    )
    s.receive_data(req_wire)
    while s.next_event() not in (h11.NEED_DATA, h11.PAUSED):
        pass
    s.send(h11.Response(status_code=200, headers=[]))
    assert s.our_state is h11.SWITCHED_PROTOCOL
    with pytest.raises(h11.LocalProtocolError):
        s.send(h11.EndOfMessage())


def test_truncated_body_on_eof_raises_remote_protocol_error() -> None:
    c = _client_request()
    c.receive_data(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab")
    c.next_event()  # Response
    c.next_event()  # partial Data
    c.receive_data(b"")  # peer half-closed
    with pytest.raises(h11.RemoteProtocolError):
        c.next_event()
    assert c.states[h11.SERVER] is h11.ERROR


def test_eof_awaiting_response_is_an_error() -> None:
    c = _client_request()
    c.receive_data(b"")
    with pytest.raises(h11.RemoteProtocolError):
        c.next_event()


def test_data_after_eof_is_a_runtime_contract_error() -> None:
    c = _client_request()
    c.receive_data(b"")
    with pytest.raises(h11.RemoteProtocolError):
        c.next_event()
    with pytest.raises(RuntimeError):
        c.receive_data(b"late bytes")


def test_repeated_eof_is_idempotent() -> None:
    c = _client_request()
    c.receive_data(b"")
    c.receive_data(b"")  # must not raise
    assert c.trailing_data == (b"", True)


def test_might_switch_buffers_bytes_without_delivering_them() -> None:
    # Server-role view: while the client's switch proposal is pending, data
    # that arrives is held and reported as PAUSED, never as an HTTP event.
    s = h11.Connection(h11.SERVER)
    s.receive_data(b"CONNECT h.example:443 HTTP/1.1\r\nHost: h.example:443\r\n\r\n")
    assert s.next_event().__class__.__name__ == "Request"
    assert s.next_event().__class__.__name__ == "EndOfMessage"
    assert s.next_event() is h11.PAUSED
    # Pipelined-looking bytes while the verdict is pending stay buffered.
    s.receive_data(b"GET / HTTP/1.0\r\n\r\n")
    assert s.next_event() is h11.PAUSED
    assert s.trailing_data == (b"GET / HTTP/1.0\r\n\r\n", False)
