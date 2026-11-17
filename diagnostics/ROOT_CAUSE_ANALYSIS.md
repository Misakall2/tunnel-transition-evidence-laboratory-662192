# Root-cause analysis: h11 message/tunnel boundary

Scope: this document explains, with references to executable evidence, how
the vendored `h11` (upstream commit `62c5068`) actually moves between HTTP
message parsing and tunnel ownership, where an integration adapter can go
wrong, and how the laboratory in `tunnellab/` proves each claim. It contains
no network access and no proxy implementation.

All claims below are reproducible with:

```
python -m pytest tunnellab_tests -q          # 112 assertions
python diagnostics/generate_evidence.py      # writes diagnostics/evidence/evidence.json
```

## 1. The library's real state changes (ground truth)

h11 models a protocol switch with two dedicated states and two sentinels.
The transitions below are asserted directly against the library in
`tunnellab_tests/test_library_state.py`; they are observed behavior, not
paraphrased documentation.

### 1.1 Proposal

When a client sends a `CONNECT` request or a request carrying an
`Upgrade:` header and then ends the request, the client role leaves `DONE`
for `MIGHT_SWITCH_PROTOCOL` while the server stays in `SEND_RESPONSE`
(`h11/_state.py`, `_fire_state_triggered_transitions`). A `PAUSED` sentinel
is now returned by `next_event` for any incoming bytes; those bytes are held
in the receive buffer and are **not** delivered as HTTP events.

### 1.2 Acceptance

* `Upgrade` acceptance is an `InformationalResponse` with status `101`.
* `CONNECT` acceptance is a `Response` with a 2xx status.

On acceptance both roles transition to `SWITCHED_PROTOCOL`
(`EVENT_TRIGGERED_TRANSITIONS` in `h11/_state.py`). From that point
`next_event()` returns `PAUSED` forever and every unprocessed byte is
exposed through `Connection.trailing_data`. The parser never consumes those
bytes (`test_tunnel_prefix_is_held_in_trailing_data_not_parsed`).

### 1.3 Rejection

Any terminal response without the matching switch annotation clears
`pending_switch_proposals` and the connection returns to the ordinary
`SEND_BODY`/`DONE` path. A denied `CONNECT` (e.g. a framed 403) is a normal
HTTP response and the connection remains reusable
(`test_denied_connect_returns_to_normal_http_and_is_reusable`). A
`SWITCHED_PROTOCOL` connection, by contrast, can never call
`start_next_cycle` (`test_switched_connection_can_never_start_a_new_cycle`).

### 1.4 The library already enforces switch consistency

A `101` or a `CONNECT`-style 2xx that was **not** proposed by the client is
rejected inside the state machine: the client raises
`RemoteProtocolError("Received server _SWITCH_UPGRADE event without a
pending proposal")` and the peer role becomes `ERROR`
(`test_unsolicited_101_is_a_library_protocol_error_not_smuggling`,
`test_unsolicited_connect_acceptance_is_rejected_by_state_machine`). This is
the crucial distinction for the smuggling question below.

## 2. Library defect versus integration error

The laboratory deliberately builds wrong adapters in
`tunnellab_tests/test_integration_errors.py` and shows that each failure
originates in caller logic while h11 behaves as documented.

| Mistake (integration layer) | What h11 actually does | Classification |
|---|---|---|
| Keep calling `next_event` after a switch expecting HTTP events | Returns `PAUSED`; bytes stay in `trailing_data` | Integration error — the caller ignored the handoff |
| Hand `MIGHT_SWITCH_PROTOCOL` buffered bytes to the request handler before the verdict | Bytes are only reachable via `trailing_data`; h11 never emits them as an event | Integration error — premature trust of unvalidated data |
| Tunnel to any authority without a trust check | h11 has no trust concept; it tracks proposals only | Integration error — policy must live outside h11 |
| Return a switched/`ERROR` connection to the keep-alive pool | `start_next_cycle` raises on switched connections; `ERROR` is terminal | Integration error — pool lifetime bug |
| Reuse one request's identity/authority for the next exchange | h11 holds no application identity at all | Integration error — context scoping bug |

No behavior exercised required modifying h11. The upstream suite continues
to pass unchanged (78 tests), which is the regression guard that the library
itself was not altered.

### Why a legal upgrade is not request smuggling

Request smuggling means one peer's parser and the other peer's parser
disagree about where a message ends, so a second message is smuggled past a
security boundary. A *solicited* `101`/`CONNECT 2xx` does not create
disagreement: the client explicitly proposed the switch, h11 records the
proposal, and on acceptance both roles deterministically move to
`SWITCHED_PROTOCOL` and stop HTTP parsing at the exact same byte boundary.
The laboratory asserts the boundary is identical under five fragmentation
strategies (`test_fragmentation_does_not_change_outcome_or_bytes`).

An *unsolicited* switch attempt — the shape a smuggler would use to escape
the HTTP parser without an agreement — is rejected by h11 itself and
classified by the adapter as a `parse` failure, never as a successful
upgrade (`test_unsolicited_101_is_classified_as_parse_failure_not_smuggling`).
Therefore the adapter reports no false smuggling alarm for legal upgrades and
no successful handoff for illegal ones.

## 3. Boundary rules the reference adapter enforces

`tunnellab/controller.py` wraps one `h11.Connection(CLIENT)` and adds the
decisions h11 intentionally leaves to the caller.

1. **Decision is bound to trusted context.** `submit_request` calls
   `SwitchPolicy.review_request(TrustContext, Request)` before any byte is
   written. A denied switch raises `SwitchRejected` and leaves the transport
   untouched (`bytes_written == 0`). Trust is carried in a per-request
   `TrustContext`, never in a mutable global.
2. **Denied switch stays on the HTTP path.** When the server answers a
   proposed switch with an ordinary response, the controller consumes the
   full response as HTTP and only recycles the connection after both roles
   reach `DONE`.
3. **Accepted switch hands bytes over exactly once.** On
   `SWITCHED_PROTOCOL` the controller drains `trailing_data` a single time
   (recorded as `tunnel_handover_count == 1`), clears h11's receive buffer
   so ownership is unambiguous, and thereafter reads bypass the parser
   entirely.
4. **Same-read boundary.** When the response terminator and the first tunnel
   bytes arrive in one network read, h11 splits them at the header block;
   the controller hands the residual prefix to the tunnel sink and asserts
   `trailing_data == (b"", ...)` afterward. No byte is parsed as HTTP after
   the switch and none is duplicated.
5. **Directional end states and reuse.** Sending and receiving EOF are
   tracked separately in `MemoryTransport`. A new request begins only after
   `start_next_cycle` returns both roles to `IDLE`. A switched connection is
   permanently retired; a failed exchange poisons reuse and atomically drops
   the request binding.
6. **Explicit failures.** Truncated bodies and header-less EOF surface as
   `ExchangeFailed(stage="parse")`; injected transport faults surface as
   `stage="read"`/`"tunnel_read"`. The failure stage is part of the evidence,
   so "peer closed early" and "read raised" are never silent truncation.
7. **Idempotent terminals.** Empty reads, repeated EOF notifications and
   repeated post-handover pumps never lose or duplicate bytes; the tunnel
   terminal latch makes the completion notification stable.

## 4. Byte accounting and fragmentation

Each scenario's wire transcript is replayed under five cuts: `whole`,
`two_halves`, `fixed_16`, `boundary_cut`, and `one_byte`. For every run the
ledger in `EventTrace` satisfies:

```
bytes_read == http_delivered + tunnel_handed_over + residual_in_h11
              + framing_consumed_by_parser
```

`framing_consumed_by_parser` is derived by subtraction, so the books balance
exactly and over-delivery is impossible
(`test_byte_conservation_balances_for_every_run`). Outcome kind, delivered
bytes and the reuse verdict are invariant across the five fragmentations.

## 5. Evidence hygiene

`EventTrace` redacts every value of `Authorization`, `Proxy-Authorization`,
`Cookie`, `Set-Cookie`, `WWW-Authenticate`, and `Proxy-Authenticate`, and
records body/tunnel payloads only as a length plus a 16-byte SHA-256 digest
prefix. `diagnostics/evidence/evidence.json` is regenerated from in-memory
transcripts; a dedicated test scans it for the secret literals and asserts
they are absent. Tunnel bodies in the transcripts are fixed synthetic
strings, not captured traffic.

## 6. What is intentionally out of scope

* No proxy, server, or command-line tool is provided; the package is a
  library plus a generator script and tests.
* No external host is contacted, resolved, or trusted. All bytes come from
  `MemoryTransport`.
* h11's public interface is unchanged; nothing in `h11/` was modified.
