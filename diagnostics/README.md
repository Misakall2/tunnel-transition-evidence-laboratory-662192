# Tunnel transition evidence laboratory

An offline diagnostic harness around the vendored [`h11`](../h11) HTTP/1.1
library. It answers one question with executable evidence: **after a proxy
hands a connection to `h11`, exactly where does message parsing end and tunnel
ownership begin for ordinary responses, `HEAD`, `CONNECT`, and protocol
upgrades — and what goes wrong when an adapter gets the boundary wrong?**

There are no sockets, no DNS, and no proxy here. Every byte flows through an
in-memory pipe, so the same conversation can be replayed under different
fragmentation and inspected deterministically.

## Layout

| Path | Purpose |
|---|---|
| `tunnellab/transport.py` | In-memory bidirectional byte pipe with directional half-close and injectable read faults |
| `tunnellab/policy.py` | Allow-list `SwitchPolicy` + per-request `TrustContext` that gate every CONNECT/Upgrade |
| `tunnellab/controller.py` | Reference adapter: policy-gated sends, single tunnel handover, explicit failure stages, binding cleanup |
| `tunnellab/pool.py` | Keep-alive pool that permanently excludes switched/failed connections |
| `tunnellab/scenarios.py` | Minimal replayable wire transcripts (ordinary, HEAD, CONNECT, upgrade, denial, disconnect) |
| `tunnellab/replay.py` | Replays each scenario under five fragmentations and checks every invariant |
| `tunnellab/trace.py` | Structured event/state/buffer/decision tracing with mandatory secret redaction |
| `tunnellab_tests/` | Pytest suite (ground-truth library tests, integration-error tests, matrix, pool, redaction) |
| `diagnostics/generate_evidence.py` | Writes `diagnostics/evidence/evidence.json` from in-memory replay only |
| `diagnostics/ROOT_CAUSE_ANALYSIS.md` | Written root-cause analysis and the defect/error taxonomy |

## Running

```bash
# Laboratory assertions plus the unchanged upstream h11 suite
python -m pytest -q

# Refresh the evidence bundle (no network access)
python diagnostics/generate_evidence.py
```

## Scenarios (all replayed under 5 fragmentations = 55 runs)

* `ordinary_get` — framed 200 body, keep-alive, exact byte delivery
* `head_no_body` — `HEAD` advertises length but yields zero body bytes
* `connect_accepted_same_read` — 200 and tunnel prefix in one read; prefix handed over once
* `connect_denied_by_server` — framed 403 stays on the HTTP path, connection reusable
* `upgrade_accepted_same_read` — `101` plus upgrade bytes in one read
* `upgrade_refused_by_server` — upgrade ignored, ordinary 200 consumed normally
* `mid_stream_disconnect` — half-close mid-body is a classified `parse` failure
* `early_close` — EOF before any response is a classified failure
* `read_failure_mid_body` — injected transport error, fragmentation independent
* `unsolicited_101` — h11 rejects an un-proposed switch (library smuggling defense)
* `pipelined_two_responses` — second response survives buffered without loss/duplication

Plus two policy-rejection checks (a blocked CONNECT authority and a blocked
upgrade token, each verified to send zero bytes) and an evidence-redaction
check.

## Design guarantees asserted by the tests

* Switch decisions are bound to a per-request, caller-supplied trust context;
  the default policy denies all switches.
* A legal, solicited upgrade is never reported as smuggling; an unsolicited
  switch is rejected by h11 and classified as a parse failure.
* Successful handover drains `trailing_data` exactly once, clears h11's
  buffer, and never feeds tunnel bytes back into the message parser.
* Rejected switches are consumed as ordinary responses before any reuse.
* Switched connections leave the keep-alive pool permanently; failures
  release the cached request and its identity binding.
* Empty reads, late data, repeated EOF and repeated completion notifications
  cause neither byte loss nor double delivery.
* Traces never contain authentication header values or tunnel payloads in the
  clear — only redaction markers, lengths, and non-reversible digests.
