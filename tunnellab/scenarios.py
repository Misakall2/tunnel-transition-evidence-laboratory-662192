"""Minimal, fully offline replay scenarios.

Each scenario is a pair of *wire transcripts* -- bytes the client writes and
bytes the (simulated) peer writes back -- plus the expectations a correct
adapter must satisfy.  Transcripts are produced with h11 itself, so they are
guaranteed to be valid framing; a handful of deliberately invalid transcripts
(unsolicited 101, truncated body, data-after-EOF) are assembled by hand to
exercise the error taxonomy.

No transcript contains authentication header values or tunnel payloads worth
secreting: tunnel bodies are fixed, obviously-synthetic byte strings.
"""

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

import h11

__all__ = [
    "Scenario",
    "Expectations",
    "FRAGMENTATIONS",
    "build_scenarios",
    "fragment",
]


@dataclass
class Expectations:
    # What the adapter should conclude.
    outcome_kind: str  # complete | switched | closed | failed
    failure_stage: Optional[str] = None
    reusable: bool = False
    # Byte accounting over the whole run.
    http_body: bytes = b""
    tunnel_prefix: bytes = b""
    tunnel_rest: bytes = b""
    http_delivery_count: Optional[int] = None
    tunnel_handover_count: int = 0
    # For policy-rejected requests: nothing is ever written.
    sends_request: bool = True
    # Library-level note distinguishing parser behavior from adapter rules.
    note: str = ""


@dataclass
class Scenario:
    name: str
    description: str
    request_wire: bytes
    peer_wire: bytes  # full stream the peer "would send"
    peer_eof_after: bool
    expectations: Expectations
    # Constructor inputs, kept so evidence can show how the transcript was made.
    request_spec: Dict[str, object] = field(default_factory=dict)
    # Whether a read failure is injected and after how many peer bytes.
    fail_after_bytes: Optional[int] = None
    fail_stage: Optional[str] = None


# ---------------------------------------------------------------------------
# Fragmentation strategies: every transcript is replayed under each of these.
# A correct adapter must deliver identical bytes, the same number of times,
# regardless of where the cuts fall.
# ---------------------------------------------------------------------------


def _one_byte_chunks(data: bytes) -> List[bytes]:
    return [bytes([b]) for b in data]


def _fixed_16_chunks(data: bytes) -> List[bytes]:
    return [data[i : i + 16] for i in range(0, len(data), 16)]


def _boundary_cut(data: bytes) -> List[bytes]:
    """Cut at the header/body boundary and at every 8 bytes inside the body."""
    sep = data.find(b"\r\n\r\n")
    if sep == -1:
        return [data]
    header_end = sep + 4
    chunks = [data[:header_end]]
    rest = data[header_end:]
    for i in range(0, len(rest), 8):
        chunks.append(rest[i : i + 8])
    return [c for c in chunks if c]


def _two_halves(data: bytes) -> List[bytes]:
    if len(data) < 2:
        return [data]
    mid = len(data) // 2
    return [data[:mid], data[mid:]]


def _whole(data: bytes) -> List[bytes]:
    return [data] if data else []


FRAGMENTATIONS: Dict[str, Callable[[bytes], List[bytes]]] = {
    "whole": _whole,
    "two_halves": _two_halves,
    "fixed_16": _fixed_16_chunks,
    "boundary_cut": _boundary_cut,
    "one_byte": _one_byte_chunks,
}


def fragment(data: bytes, strategy: str) -> List[bytes]:
    return FRAGMENTATIONS[strategy](data)


# ---------------------------------------------------------------------------
# Transcript builders
# ---------------------------------------------------------------------------


def _client_wire(
    method: str,
    target: str,
    headers: List[Tuple[str, str]],
    body: bytes = b"",
) -> bytes:
    conn = h11.Connection(h11.CLIENT)
    wire = conn.send(h11.Request(method=method, target=target, headers=headers))
    if body:
        wire += conn.send(h11.Data(data=body))
    return wire + conn.send(h11.EndOfMessage())


def _server_wire(events: List[h11.Event], request_wire: Optional[bytes] = None) -> bytes:
    conn = h11.Connection(h11.SERVER)
    if request_wire is not None:
        # Process the request first so method-dependent framing (HEAD,
        # CONNECT) matches what a real peer would emit.
        conn.receive_data(request_wire)
        while True:
            event = conn.next_event()
            if event in (h11.NEED_DATA, h11.PAUSED):
                break
    out = b""
    for event in events:
        chunk = conn.send(event)
        if chunk is not None:
            out += chunk
    return out


# Synthetic, non-secret tunnel payloads.
TLS_HELLO_PREFIX = b"\x16\x03\x03\x00\x2a"  # looks like TLS, contains no secret
TUNNEL_TAIL = b"raw-tunnel-bytes-0123456789"


def build_scenarios() -> List[Scenario]:
    scenarios: List[Scenario] = []

    # 1) Ordinary GET with Content-Length, keep-alive, then reuse.
    get_headers = [("Host", "example.test"), ("Content-Length", "0")]
    get_req = _client_wire("GET", "/index", get_headers)
    get_resp = _server_wire(
        [
            h11.Response(status_code=200, headers=[("Content-Length", "11")]),
            h11.Data(data=b"hello-world"),
            h11.EndOfMessage(),
        ],
        request_wire=get_req,
    )
    scenarios.append(
        Scenario(
            name="ordinary_get",
            description="GET with framed 200 body; connection stays reusable",
            request_wire=get_req,
            peer_wire=get_resp,
            peer_eof_after=False,
            expectations=Expectations(
                outcome_kind="complete",
                reusable=True,
                http_body=b"hello-world",
                http_delivery_count=1,
            ),
            request_spec={
                "method": "GET", "target": "/index", "headers": list(get_headers)
            },
        )
    )

    # 2) HEAD: no body may be delivered even if framing headers are present.
    head_headers = [("Host", "example.test"), ("Content-Length", "0")]
    head_req = _client_wire("HEAD", "/resource", head_headers)
    head_resp = _server_wire(
        [
            h11.Response(status_code=200, headers=[("Content-Length", "99")]),
            h11.EndOfMessage(),
        ],
        request_wire=head_req,
    )
    scenarios.append(
        Scenario(
            name="head_no_body",
            description="HEAD response advertises length but yields zero body bytes",
            request_wire=head_req,
            peer_wire=head_resp,
            peer_eof_after=False,
            expectations=Expectations(
                outcome_kind="complete",
                reusable=True,
                http_body=b"",
                http_delivery_count=0,
            ),
            request_spec={
                "method": "HEAD", "target": "/resource", "headers": list(head_headers)
            },
        )
    )

    # 3) CONNECT accepted; tunnel prefix shares the read with the 200 end.
    connect_headers = [("Host", "allowed.example:443")]
    connect_req = _client_wire("CONNECT", "allowed.example:443", connect_headers)
    # A real CONNECT peer emits just the 200 header block and then speaks the
    # tunnel protocol; h11 itself refuses EndOfMessage after an accepted
    # switch, so the transcript contains no HTTP end-of-message marker.
    connect_accept = _server_wire(
        [h11.Response(status_code=200, headers=[])],
        request_wire=connect_req,
    )
    scenarios.append(
        Scenario(
            name="connect_accepted_same_read",
            description=(
                "CONNECT 200 and first tunnel bytes arrive in one network read; "
                "prefix must be handed over exactly once"
            ),
            request_wire=connect_req,
            peer_wire=connect_accept + TLS_HELLO_PREFIX + TUNNEL_TAIL,
            peer_eof_after=True,
            expectations=Expectations(
                outcome_kind="switched",
                reusable=False,
                tunnel_prefix=TLS_HELLO_PREFIX + TUNNEL_TAIL,
                tunnel_rest=b"",
                tunnel_handover_count=1,
            ),
            request_spec={
                "method": "CONNECT",
                "target": "allowed.example:443",
                "headers": list(connect_headers),
            },
        )
    )

    # 4) CONNECT denied by the *server* (403 with a framed body): ordinary
    #    response path, keep-alive, no tunnel handover.
    denied_resp = _server_wire(
        [
            h11.Response(status_code=403, headers=[("Content-Length", "9")]),
            h11.Data(data=b"forbidden"),
            h11.EndOfMessage(),
        ],
        request_wire=connect_req,
    )
    scenarios.append(
        Scenario(
            name="connect_denied_by_server",
            description=(
                "Server rejects CONNECT with a framed 403; bytes stay on the "
                "HTTP path and the connection can be reused"
            ),
            request_wire=connect_req,
            peer_wire=denied_resp,
            peer_eof_after=False,
            expectations=Expectations(
                outcome_kind="complete",
                reusable=True,
                http_body=b"forbidden",
                http_delivery_count=1,
                tunnel_handover_count=0,
            ),
            request_spec={
                "method": "CONNECT",
                "target": "allowed.example:443",
                "headers": list(connect_headers),
            },
        )
    )

    # 5) Upgrade accepted with 101; prefix in same read.
    upgrade_headers = [
        ("Host", "example.test"),
        ("Connection", "Upgrade"),
        ("Upgrade", "websocket"),
        ("Content-Length", "0"),
    ]
    upgrade_req = _client_wire("GET", "/chat", upgrade_headers)
    upgrade_accept = (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    )
    scenarios.append(
        Scenario(
            name="upgrade_accepted_same_read",
            description="101 response plus websocket bytes in a single read",
            request_wire=upgrade_req,
            peer_wire=upgrade_accept + b"websocket-frame-1" + b"websocket-frame-2",
            peer_eof_after=True,
            expectations=Expectations(
                outcome_kind="switched",
                reusable=False,
                tunnel_prefix=b"websocket-frame-1websocket-frame-2",
                tunnel_handover_count=1,
            ),
            request_spec={
                "method": "GET",
                "target": "/chat",
                "headers": list(upgrade_headers),
                "upgrade": "websocket",
            },
        )
    )

    # 6) Upgrade offered by client, refused by server (ordinary 200).
    upgrade_refused_resp = _server_wire(
        [
            h11.Response(status_code=200, headers=[("Content-Length", "4")]),
            h11.Data(data=b"http"),
            h11.EndOfMessage(),
        ],
        request_wire=upgrade_req,
    )
    scenarios.append(
        Scenario(
            name="upgrade_refused_by_server",
            description="Server ignores Upgrade and answers a normal 200",
            request_wire=upgrade_req,
            peer_wire=upgrade_refused_resp,
            peer_eof_after=False,
            expectations=Expectations(
                outcome_kind="complete",
                reusable=True,
                http_body=b"http",
                http_delivery_count=1,
                tunnel_handover_count=0,
            ),
            request_spec={
                "method": "GET",
                "target": "/chat",
                "headers": list(upgrade_headers),
                "upgrade": "websocket",
            },
        )
    )

    # 7) Mid-stream disconnect: full headers, truncated body, then EOF.
    truncated_resp = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab"
    )
    scenarios.append(
        Scenario(
            name="mid_stream_disconnect",
            description="Peer half-closes mid-body; truncation must be a failure",
            request_wire=get_req,
            peer_wire=truncated_resp,
            peer_eof_after=True,
            expectations=Expectations(
                outcome_kind="failed",
                failure_stage="parse",
                reusable=False,
                http_body=b"",  # partial data must not be accepted as a body
            ),
            request_spec={
                "method": "GET", "target": "/index", "headers": list(get_headers)
            },
        )
    )

    # 8) Early close while still waiting for response headers.
    scenarios.append(
        Scenario(
            name="early_close",
            description="Peer closes before sending any response",
            request_wire=get_req,
            peer_wire=b"",
            peer_eof_after=True,
            expectations=Expectations(
                outcome_kind="failed",
                failure_stage="parse",
                reusable=False,
            ),
            request_spec={
                "method": "GET", "target": "/index", "headers": list(get_headers)
            },
        )
    )

    # 9) Injected transport read failure mid-body.
    partial = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\npart1-part2-xxxx"
    )
    scenarios.append(
        Scenario(
            name="read_failure_mid_body",
            description="Synthetic read error after partial body delivery",
            request_wire=get_req,
            peer_wire=partial,
            peer_eof_after=False,
            fail_after_bytes=20,
            fail_stage="read",
            expectations=Expectations(
                outcome_kind="failed",
                failure_stage="read",
                reusable=False,
            ),
            request_spec={
                "method": "GET", "target": "/index", "headers": list(get_headers)
            },
        )
    )

    # 10) Unsolicited 101: library-level smuggling defense. No Upgrade was
    #     requested, so h11 itself must raise; this is NOT a false positive.
    plain_headers = [("Host", "example.test"), ("Content-Length", "0")]
    plain_req = _client_wire("GET", "/plain", plain_headers)
    scenarios.append(
        Scenario(
            name="unsolicited_101",
            description=(
                "101 without an Upgrade proposal: h11 rejects it as a protocol "
                "error; a correct adapter must not call this request smuggling"
            ),
            request_wire=plain_req,
            peer_wire=upgrade_accept + b"smuggled?",
            peer_eof_after=False,
            expectations=Expectations(
                outcome_kind="failed",
                failure_stage="parse",
                reusable=False,
                note="library-enforced switch consistency, not a smuggling report",
            ),
            request_spec={
                "method": "GET", "target": "/plain", "headers": list(plain_headers)
            },
        )
    )

    # 11) Pipelined second response already in the buffer when the first
    #     exchange ends (late data / repeated completion safety).
    second_resp = _server_wire(
        [
            h11.Response(status_code=200, headers=[("Content-Length", "6")]),
            h11.Data(data=b"second"),
            h11.EndOfMessage(),
        ],
        request_wire=get_req,
    )
    scenarios.append(
        Scenario(
            name="pipelined_two_responses",
            description=(
                "Two full responses arrive back to back; bytes for the second "
                "exchange survive in h11's buffer without loss or duplication"
            ),
            request_wire=get_req,
            peer_wire=get_resp + second_resp,
            peer_eof_after=False,
            expectations=Expectations(
                outcome_kind="complete",
                reusable=True,
                http_body=b"hello-world",
                http_delivery_count=1,
                note="second response remains buffered, verified in test",
            ),
            request_spec={
                "method": "GET", "target": "/index", "headers": list(get_headers),
            },
        )
    )

    return scenarios


def policy_rejection_scenarios() -> List[Dict[str, object]]:
    """Requests the local policy must stop before a single byte is sent."""
    return [
        {
            "name": "policy_rejects_connect_target",
            "method": "CONNECT",
            "target": "blocked.example:443",
            "headers": [("Host", "blocked.example:443")],
        },
        {
            "name": "policy_rejects_upgrade_token",
            "method": "GET",
            "target": "/chat",
            "headers": [
                ("Host", "example.test"),
                ("Connection", "Upgrade"),
                ("Upgrade", "evil-proto"),
            ],
        },
    ]


def authenticated_request_spec() -> Dict[str, object]:
    """A request carrying a secret header, used only by the redaction test."""
    return {
        "method": "GET",
        "target": "/private",
        "headers": [
            ("Host", "example.test"),
            ("Authorization", "Bearer super-secret-token-1234"),
            ("Proxy-Authorization", "Basic dXNlcjpwYXNz"),
            ("Cookie", "session=top-secret"),
            ("X-Trace", "non-secret"),
        ],
    }
