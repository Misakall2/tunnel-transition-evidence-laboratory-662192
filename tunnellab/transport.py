"""In-memory bidirectional byte transport for offline diagnostics.

This module contains *no* socket code and performs *no* I/O against external
hosts.  A :class:`MemoryTransport` is one endpoint of a pair created by
:func:`make_transport_pair`; bytes written to one endpoint appear, unchanged,
at the other endpoint, and can be read back with configurable fragmentation.

Directional half-close state is tracked separately for each direction so that
diagnostics can distinguish "peer stopped writing" from "fully closed", and a
synthetic read failure can be injected to exercise error paths
(:class:`ReadFailure`) without touching the operating system.
"""

from collections import deque
from dataclasses import dataclass
from typing import Deque, List, Optional, Tuple

__all__ = [
    "ReadFailure",
    "MemoryTransport",
    "TransportClosed",
    "make_transport_pair",
]


class TransportClosed(Exception):
    """Raised when reading from a direction whose peer side is fully gone."""


class ReadFailure(Exception):
    """Synthetic transport-level failure injected by the diagnostic harness.

    It stands in for the errors a real adapter would see (reset, timeout,
    TLS alert, ...).  ``stage`` records where in the exchange the failure was
    injected so the evidence report can name the failure phase precisely.
    """

    def __init__(self, stage: str, reason: str = "injected read failure") -> None:
        super().__init__(f"{stage}: {reason}")
        self.stage = stage
        self.reason = reason


@dataclass
class _Pipe:
    """One directional byte stream with separate close tracking."""

    chunks: Deque[bytes]
    write_closed: bool = False

    def __init__(self) -> None:
        self.chunks = deque()
        self.write_closed = False


class MemoryTransport:
    """One endpoint of an in-memory connection.

    ``write`` enqueues bytes for the peer; ``read`` drains bytes that the
    peer wrote to this endpoint.  The two directions are independent: calling
    :meth:`write_eof` only closes *our write side* (the peer's read side),
    mirroring ``shutdown(SHUT_WR)`` on a real socket.
    """

    def __init__(self, name: str, incoming: _Pipe, outgoing: _Pipe) -> None:
        self._name = name
        self._incoming = incoming  # what the peer writes, we read
        self._outgoing = outgoing  # what we write, the peer reads
        self._fail_once: Optional[ReadFailure] = None
        self._fail_every: Optional[ReadFailure] = None
        # Fault once total bytes read crosses this threshold (fragmentation
        # independent); None disables it.
        self._fail_after_total: Optional[Tuple[int, ReadFailure]] = None
        self.bytes_written = 0
        self.bytes_read = 0
        self.eof_delivered = False
        # Snapshot of every write call (chunks preserved, not coalesced).
        self.write_history: List[bytes] = []

    # -- write side -------------------------------------------------------

    def write(self, data: bytes) -> int:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("transport only accepts bytes-like objects")
        if self._outgoing.write_closed:
            raise TransportClosed(
                f"{self._name}: write after local write-side close"
            )
        data = bytes(data)
        if data:
            self._outgoing.chunks.append(data)
            self.bytes_written += len(data)
            self.write_history.append(data)
        return len(data)

    def write_eof(self) -> None:
        """Half-close our write direction (peer sees EOF on its reads)."""
        self._outgoing.write_closed = True

    @property
    def write_side_closed(self) -> bool:
        return self._outgoing.write_closed

    # -- read side --------------------------------------------------------

    def fail_next_read(self, failure: ReadFailure) -> None:
        """Arrange for the very next :meth:`read` to raise ``failure``."""
        self._fail_once = failure

    def fail_all_reads(self, failure: ReadFailure) -> None:
        """Arrange for every subsequent :meth:`read` to raise ``failure``."""
        self._fail_every = failure

    def fail_after_total_bytes(
        self, threshold: int, failure: ReadFailure
    ) -> None:
        """Raise ``failure`` on the first read that crosses ``threshold``
        total bytes, regardless of how the stream is fragmented."""
        self._fail_after_total = (threshold, failure)

    def _threshold_failure_for(self, incoming_len: int) -> Optional[ReadFailure]:
        """Return the fault to raise when reading would reach or cross the
        byte threshold; otherwise None."""
        if self._fail_after_total is None:
            return None
        threshold, failure = self._fail_after_total
        if self.bytes_read + incoming_len >= threshold:
            # One-shot: disarm so the fault is raised exactly once.
            self._fail_after_total = None
            return failure
        return None

    def read(self, max_bytes: Optional[int] = None) -> bytes:
        """Return at most ``max_bytes`` buffered bytes.

        Returns ``b""`` exactly once per direction when the peer has
        half-closed and the buffer is drained; subsequent reads keep
        returning ``b""`` (the h11 convention treats repeated empty reads as
        idempotent).  Raises an injected :class:`ReadFailure` if armed.
        """
        if self._fail_every is not None:
            raise self._fail_every
        if self._fail_once is not None:
            failure = self._fail_once
            self._fail_once = None
            raise failure
        if not self._incoming.chunks:
            if self._incoming.write_closed:
                self.eof_delivered = True
                return b""
            # Nothing available yet, peer still alive: callers distinguish
            # this from EOF via read_some() which returns None.
            return b""
        chunk = self._incoming.chunks.popleft()
        if max_bytes is not None and len(chunk) > max_bytes:
            self._incoming.chunks.appendleft(chunk[max_bytes:])
            chunk = chunk[:max_bytes]
        threshold_failure = self._threshold_failure_for(len(chunk))
        if threshold_failure is not None:
            # Put the chunk back: zero bytes are delivered on a failing read.
            self._incoming.chunks.appendleft(chunk)
            raise threshold_failure
        self.bytes_read += len(chunk)
        return chunk

    def read_some(self, max_bytes: Optional[int] = None) -> Optional[bytes]:
        """Like :meth:`read` but returns ``None`` when no data and no EOF.

        ``None`` means "no progress possible right now"; ``b""`` means the
        peer half-closed.  This mirrors non-blocking socket APIs where an
        empty read is *not* necessarily EOF.
        """
        if self._fail_every is not None:
            raise self._fail_every
        if self._fail_once is not None:
            failure = self._fail_once
            self._fail_once = None
            raise failure
        if not self._incoming.chunks:
            if self._incoming.write_closed:
                self.eof_delivered = True
                return b""
            return None
        return self.read(max_bytes)

    @property
    def peer_write_closed(self) -> bool:
        return self._incoming.write_closed

    @property
    def buffered_bytes(self) -> int:
        return sum(len(c) for c in self._incoming.chunks)

    def drain_all(self) -> bytes:
        """Test helper: read every currently buffered byte."""
        parts: List[bytes] = []
        while True:
            part = self.read_some()
            if part is None or part == b"":
                break
            parts.append(part)
        return b"".join(parts)


def make_transport_pair(
    name_a: str = "a", name_b: str = "b"
) -> Tuple[MemoryTransport, MemoryTransport]:
    """Create two connected, fully in-memory transports."""
    a_to_b = _Pipe()
    b_to_a = _Pipe()
    return (
        MemoryTransport(name_a, incoming=b_to_a, outgoing=a_to_b),
        MemoryTransport(name_b, incoming=a_to_b, outgoing=b_to_a),
    )
