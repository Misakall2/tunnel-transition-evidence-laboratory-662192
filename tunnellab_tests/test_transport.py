"""Tests for the in-memory transport: fragmentation, half-close and faults.

These establish the ground truth every higher-level assertion relies on:
the transport delivers the exact byte sequence once, in order, regardless of
where chunk boundaries fall, and reports directional EOF deterministically.
"""

import pytest

from tunnellab.transport import (
    ReadFailure,
    TransportClosed,
    make_transport_pair,
)


def test_bytes_round_trip_unchanged_and_in_order() -> None:
    a, b = make_transport_pair("a", "b")
    a.write(b"hello ")
    a.write(b"world")
    assert b.read_some() == b"hello "
    assert b.read_some() == b"world"
    # Nothing left, peer still alive -> None, not EOF.
    assert b.read_some() is None
    assert b.bytes_read == 11


def test_half_close_is_directional() -> None:
    a, b = make_transport_pair("a", "b")
    a.write(b"x")
    a.write_eof()
    assert b.read_some() == b"x"
    # Buffered data drained; now the peer write-side closure is visible.
    assert b.read_some() == b""
    assert b.peer_write_closed is True
    # Repeated empty reads are idempotent, never raise.
    assert b.read_some() == b""
    # The other direction is still open: b can still write to a.
    b.write(b"back")
    assert a.read_some() == b"back"


def test_write_after_close_rejected() -> None:
    a, b = make_transport_pair("a", "b")
    a.write_eof()
    with pytest.raises(TransportClosed):
        a.write(b"late")


def test_data_after_eof_is_a_contract_error() -> None:
    a, b = make_transport_pair("a", "b")
    a.write_eof()
    assert b.read_some() == b""
    # Mirroring h11's receive_data rule: more bytes after EOF cannot happen.
    with pytest.raises(TransportClosed):
        a.write(b"resurrected")


def test_empty_write_is_a_noop() -> None:
    a, b = make_transport_pair("a", "b")
    assert a.write(b"") == 0
    assert a.bytes_written == 0
    assert b.read_some() is None


def test_fault_fires_once_and_delivers_nothing_on_failing_read() -> None:
    a, b = make_transport_pair("a", "b")
    a.write(b"0123456789")
    b.fail_after_total_bytes(4, ReadFailure("read", "boom"))
    # Whole 10-byte chunk would cross the threshold of 4 -> fault, no bytes.
    with pytest.raises(ReadFailure) as excinfo:
        b.read_some()
    assert excinfo.value.stage == "read"
    # One-shot fault disarmed; the chunk is still intact (nothing lost).
    assert b.bytes_read == 0
    assert b.read_some() == b"0123456789"
    assert b.bytes_read == 10


def test_threshold_fault_is_fragmentation_independent() -> None:
    payload = bytes(range(40))
    for cuts in (
        [payload],
        [payload[:20], payload[20:]],
        [payload[i : i + 7] for i in range(0, len(payload), 7)],
        [bytes([x]) for x in payload],
    ):
        a, b = make_transport_pair("a", "b")
        for chunk in cuts:
            a.write(chunk)
        b.fail_after_total_bytes(25, ReadFailure("read", "cut"))
        delivered = 0
        with pytest.raises(ReadFailure):
            while True:
                chunk = b.read_some()
                if chunk is None:
                    break
                delivered += len(chunk)
        # The fault interrupts at or before the threshold, never past it.
        assert delivered <= 25
        # Remaining bytes are preserved without duplication or loss.
        rest = b.drain_all()
        assert delivered + len(rest) == len(payload)


def test_fail_next_read_is_single_shot() -> None:
    a, b = make_transport_pair("a", "b")
    a.write(b"abc")
    b.fail_next_read(ReadFailure("read", "once"))
    with pytest.raises(ReadFailure):
        b.read_some()
    # Subsequent reads behave normally.
    assert b.read_some() == b"abc"
