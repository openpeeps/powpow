# powpow — Security Audit Report

**Date:** 2026-08-08
**Scope:** `powpow` 0.1.8 (`src/`) + the `multipart` 0.1.4 dependency
(`../../multipart`), which powpow builds against byte-for-byte.
**Method:** full source review, review of all existing tests, and runtime PoC
confirmation of every finding before fixing. All PoCs are preserved as runnable
regression tests in this `audit/` directory.

## Threat model

Unauthenticated remote client sending arbitrary bytes to HTTP/WS/TCP/UDP
endpoints, plus unauthenticated file uploads (multipart / raw-body streaming).
Impact classes: memory safety, request smuggling/desync, remote crash (DoS),
resource exhaustion (RAM/disk/connections), path traversal, local file
disclosure/clobber via temp files.

## Baseline

- `multipart/tests/test1.nim` — all pass (pre-fix and post-fix).
- powpow `tests/*.nim` — all pass (pre-fix and post-fix).
- `smuggler` differential test (powpow vs. an independent RFC-strict parser,
  1161 network requests) — **0 discrepancies** pre- and post-fix.

## P0 — Confirmed & fixed

### 1. Remote crash: multipart `IndexDefect` on malformed part headers
`multipart.nim` `parseHeader` (src:285-286), `createPart` (streamer), and the
buffered `parseBoundary` branch indexed into parsed header tuples without
checking that the required `name=`/`filename=`/Content-Type value actually
exists. Inputs such as:

```
Content-Disposition: form-data; name        (parameter without '=')
Content-Disposition: form-data              (no parameters at all)
Content-Disposition: form-data; name="f"    (file part, no filename)
```

raised `IndexDefect` (a *Defect*, not a CatchableError). Because powpow's
auto-streaming upload path calls `ms[].feed(data)` from inside the event loop
(`httpserver.nim:909`) and `getMultipart()` (`http.nim`) from handlers, the
Defect escaped the loop and **terminated the whole process**. Verified: the
PoC server process aborted with `unhandled exception: index 1 not in 0 .. 0
[IndexDefect]` in the pre-fix build.

**Fix:** all three paths now validate the parsed tuples and raise
`MultipartInvalidHeader` (CatchableError). powpow catches it
(`httpserver.nim` feed + auto-stream, `http.nim` `getMultipart`) and replies
400/413 instead of crashing.
**Regression tests:** `audit/multipart_parser_crash.nim`,
`audit/powpow_multipart_server.nim`, `multipart/tests/test_security.nim`,
`tests/test_security.nim` (`test_malformed_multipart_part_does_not_crash_server`).

### 2. Remote crash: buffered `parse()` on a body without a leading boundary
`multipart.nim:616` (`mp.boundaries[^1]`) indexed an empty sequence when the
body began with preamble or garbage → `IndexDefect`. Not reachable through
powpow's streaming path, but part of the public API.
**Fix:** guard `mp.boundaries.len == 0` (skip preamble bytes).
**Regression tests:** `audit/multipart_buffered_crash.nim`,
`multipart/tests/test_security.nim`.

### 3. Chunked streaming bodies never completed (and forwarded raw framing)
`http.nim` streaming branch forwarded raw chunk bytes to `onBodyData`, never
parsed the terminating chunk, and never called `done=true`. A chunked request
with `onBodyData` set stayed in `PhaseBody` forever (hang until read timeout).
**Fix:** chunked bodies are buffered + decoded; `onBodyData` receives the
decoded bytes with `done=true` on completion. `parseChunkedBody` now advances
`bodyStart` past the final CRLF so `resetForNext`/`getRemainingData` no longer
leave the chunk terminator in the buffer.
**Regression tests:** `audit/chunked_streaming.nim`,
`tests/test_security.nim` (`test_chunked_streaming_delivers_decoded_data`,
`test_chunked_keepalive_next_request_parses`).

### 4. Chunked upload unbounded when `maxBodySize == 0`
`parseChunkedBody` only enforced the cap when `maxBodySize > 0`. With the
default server config (`maxBodySize=0`) a chunked upload buffered without
limit (RAM/disk). Now capped at `MaxStreamBodySize` (512 MB) even when
`maxBodySize == 0`.
**Regression tests:** `audit/chunked_streaming.nim`,
`tests/test_security.nim` (`test_chunked_body_unlimited_capped`).

## P1 — Confirmed & fixed

### 5. `serveStatic` broken prefix handling + sibling-prefix leak
`serveStatic` (a) rejected every legitimate request when the documented
`urlPrefix` had no trailing slash (`relPath[0] == '/'` guard) and (b) matched
`urlPrefix` with a bare `startsWith`, so `/staticx/file` was **served** from
`fsRoot/x/file` while `/static/file` got 403. Verified over the wire
(`/staticx/file.txt → 200 body='LEAKED'`).
**Fix:** match the prefix at a path-component boundary (both `/static` and
`/static/` accepted), strip the separator slash, and keep the existing
`..`/`~`/symlink guards.
**Regression tests:** `audit/serve_static.nim`.

### 6. Slow-read memory DoS: unbounded per-connection write buffer
`tcp.nim` `send`/`sendv` appended to `conn.writeBuf` without a cap. A client
that stops reading while the server writes a large response (notably a TLS
file download) accumulates the whole payload per connection.
**Fix:** `queueWrite` caps the buffer at `MaxWriteBufferSize` (32 MB) and
closes the connection beyond it.
**Regression test:** existing `test_net`/`test_tls` (no regressions).

### 7. Temp upload files world-readable (0644) + symlink-following open
multipart file writes, `req.streamToFile()`, and the http-server session temp
file all used `open(..., fmWrite)` → 0644 (world-readable upload content) and
followed a pre-planted symlink (local clobber of an arbitrary file).
Verified: created temp file had `{fpUserWrite, fpUserRead, fpGroupRead,
fpOthersRead}`.
**Fix:** new `multipart.openPrivateFile*` — POSIX `open(..., O_CREAT|O_EXCL|
O_WRONLY, 0o600)` + `fdopen`; used by all three write sites with a bounded
OID retry on `EEXIST`.
**Regression tests:** `audit/tempfile_permissions.nim`,
`multipart/tests/test_security.nim`.

## P2 — Addressed

### 8. `maxFieldSize` not wired through powpow
`httpserver.nim` built the multipart `sizeLimit` with only
`maxBodySize`/`maxFileSize`; a hostile text field could consume ~512 MB RAM per
connection. Added `HttpServer.maxFieldSize*` and threaded it into the limit.
**Regression test:** covered by the existing multipart size-limit tests.

## HTTP/2 audit (server-side; `http2client.nim` out of scope)

Harnesses: `audit/h2_*.nim` (live h2c server + raw frame peer, plus
white-box HPACK decoder tests). Prior coverage in
`tests/test_http2_security.nim` (13 cases) was taken as given; the audits
below close the remaining gaps.

### P1 — Confirmed & fixed

**9. CONTINUATION bomb: unbounded `fragBuf` per stream.**
`handleContinuation` appended every fragment until END_HEADERS; the
`maxHeaderList` (16 KB) check ran only after full HPACK decode — 8 MB of
fragments grew server RSS ~35 MB with no gate engaged (slow-dripped, held
indefinitely). Fix (`http2conn.nim`): CONTINUATION bytes are accounted
against `maxHeaderList` + one frame of framing slop incrementally, at the
fragment-open points and before every append; excess refuses the stream
with `COMPRESSION_ERROR` (RFC 7540 §4.3) and resets the fragment state.
Single-block oversize still takes the existing 431 path.
**Regression test:** `audit/h2_continuation_bomb.nim` (was: +35 MB RSS;
now: +120 KB, early RST, follow-up 200).

### Pins (verified secure, locked by harness)

- **HPACK decoder** (`audit/h2_hpack_hostile.nim`, 13 cases): overlong/
  truncated/too-large integers, reserved/huge indexes, truncated and
  4 MB+ string lengths (raises *before* allocating), empty block — all
  `HpackError`, never `IndexDefect`.
- **Huffman decoder** (`audit/h2_hpack_bad_huffman.nim`, 10 cases): EOS,
  invalid codes, zero/overlong padding all raise. Ones-padding acceptance
  (e.g. `0x1F` → `"a"`) is RFC 7541 §5.2-mandated leniency, pinned.
- **Dynamic table** (`audit/h2_hpack_table_accounting.nim`, 8 cases):
  eviction shifting, size-update lowering/zeroing/over-limit, oversized
  entry drain, never-indexed privacy. Mid-block size updates accepted
  (§4.2 says they must open the block) — harmless decoder leniency, pinned.
- **Stream machine** (`audit/h2_stream_machine.nim`, 6 cases): RST/DATA/
  WINDOW_UPDATE on idle → `PROTOCOL_ERROR` GOAWAY; on closed → silent/RST;
  DATA after END_STREAM → stream RST, conn healthy; trailers without
  END_STREAM → GOAWAY; post-client-GOAWAY streams REFUSED, old streams work.
- **Upgrade strictness** (`audit/h2_upgrade_strict.nim`, 7 cases): garbage
  or mis-sized base64 → close, no dispatch; hostile embedded
  `INITIAL_WINDOW_SIZE` → close; upgrade with body → 400; 10 KB headers
  hit the 8 KB sniff cap; valid upgrade 101s. `Transfer-Encoding` on the
  upgrade 101s but fails closed at dispatch (`PROTOCOL_ERROR`, handler
  never runs) — correct.
- **Flow control** (`audit/h2_flow_control.nim`): 128 KB burst absorbed
  with byte-exact accounting; `INITIAL_WINDOW_SIZE=0` stalls responses
  until WINDOW_UPDATE. Note: the connection-level `FLOW_CONTROL_ERROR`
  backstop is unreachable under the eager top-up policy (minimum window
  at the check is 32767 > max frame 16384) — defense in depth, not a live
  path.
- **Frame layer** (`audit/h2_frame_size.nim`, 7 cases): oversize DATA,
  short PING, non-empty SETTINGS ACK → `FRAME_SIZE_ERROR`; split arrival
  reassembles byte-exact; incomplete frames stall per-connection only
  (second conn unaffected) and complete exactly later; valid padding
  accepted, over-pad → `PROTOCOL_ERROR`; unknown extension types ignored.
  Harness lesson: frame bytes must be contiguous on the wire — the
  `h2peer` auto-SETTINGS-ACK interleaved a split DATA frame during
  development and correctly produced `FRAME_SIZE_ERROR` (server right,
  test wrong).
- **GOAWAY discipline** (`audit/h2_goaway_drain.nim`, 3 cases):
  `lastStreamId` exact for completed and in-flight streams; post-teardown
  frames discarded, no resurrection.

### Finding with proposed limits (not implemented)

- **No generic H2 rate limiter** (`audit/h2_flood_policy.nim`): 5k PINGs
  acked 1:1 in 97 ms, 5k empty SETTINGS acked, 5k closed-stream RSTs
  silent, 512-stream open/RST churn drains `openCount` to zero — all
  bounded, no superlinear cost, follow-ups healthy. Residual risk is
  CPU-for-packets at line rate (same profile as an H1 GET flood),
  bounded per vector by existing caps (128 concurrent streams, 16 KB
  header list, 16 KB frames, 8 MB bodies). Proposed: lifetime budgets
  per connection (~10k PINGs/SETTINGS) → `ENHANCE_YOUR_CALM` GOAWAY;
  RSTs need nothing (already O(1)).

## Previously-reported findings verified already fixed (from security-improvements.md)

- Content-Length overflow off-by-one (`http.nim` saturating parse + `contentEnd`) — fixed, tested.
- Dead read/keep-alive timeouts — replaced by a lazy server-wide timeout sweep — fixed, tested.
- `serveFile` sibling-prefix confusion — fixed (`fsRoot & "/"` boundary), tested.
- `sendFile` fixed-size stack header buffer overflow — replaced with a growing seq buffer, tested.
- WS unbounded allocation when `maxFrameSize == 0` — `WsHardMaxFrameSize` cap, tested.
- Allocation-before-header-limits — `HeaderBufCap` bound, tested.
- Disk fill via unbounded auto-stream — `MaxStreamBodySize` cap, tested.
- Rate-limiter table race in `MultiThreadHttpServer` — `Lock` added, threaded test added.

## False positives (investigated, verified NOT vulnerable)

- **Timer-wheel cancellation set cleared early** — `loop.nim:388` clear condition
  is unreachable (`cancelled ⊆ totalTimers`); 500 cancelled long timers fired 0
  times. Pinned by `audit/timer_cancel_regression.nim`.
- **Chunked decode buffer overlap** — destination always precedes source; safe.
- **Field-name quoting** — Nim `strutils.unescape` strips the surrounding quotes;
  `b.fieldName == "upload"` holds (all multipart tests green).

## Remaining recommendations (not fixed — config or platform)

- **Windows static-serving symlink escape** (`resolveReal` falls back to
  `absolutePath` on Windows, which does not resolve symlinks). The symlink guard
  is effective on POSIX; Windows needs `GetFinalPathNameByHandle`-style
  canonicalization or documented opt-out.
- **`maxBodySize == 0` still allows 512 MB per connection** of RAM/disk before
  413 (`MaxStreamBodySize`). Operators should set explicit
  `server.maxBodySize`/`maxFileSize`/`maxFieldSize` for public endpoints.
- **WebSocket server has no post-upgrade idle/read timeout** (only a handshake
  timeout); an idle upgraded connection persists indefinitely.
- **`parseRange` leniency** (`bytes=0-5garbage` ignores the trailing garbage);
  `udp` `send`/`sendTo` with an empty payload reads `data[0]` (harmless, but
  `unsafeAddr` of an empty seq).

## Files changed

- `multipart/src/multipart.nim` — crash-proof header/part parsing, `openPrivateFile`, guards.
- `multipart/multipart.nimble` — 0.1.3 → 0.1.4.
- `multipart/tests/test_security.nim` — new.
- `powpow/src/powpow/proto/http.nim` — chunked streaming completion, `resetForNext`/`getRemainingData` framing, `MaxStreamBodySize` cap, `getMultipart` error handling, private temp files.
- `powpow/src/powpow/proto/httpserver.nim` — catch `MultipartInvalidHeader`, `maxFieldSize`, private session temp files, `serveStatic` prefix fix.
- `powpow/src/powpow/net/tcp.nim` — `queueWrite` cap.
- `powpow/powpow.nimble` — `multipart >= 0.1.4`.
- `powpow/tests/test_security.nim` — new regression tests.
- `powpow/audit/` — runnable regression harness (this directory).

## Performance — macOS `Connection: close` regression (root-caused + fixed)

**Root cause: commit `7b51b9a` "try fix on ubuntu".** It changed
`closeAfterDrain` (tcp.nim) so non-TLS connections perform a graceful FIN close
(`shutdown()` + wait for the peer's FIN) instead of the immediate SO_LINGER=0
RST close. That was a Linux correctness fix (RST can drop the peer's unread
receive buffer), but on **macOS/kqueue it collapses `Connection: close`
throughput ~8x** (3.3K vs ~27K req/s) under a wrk-style load generator.
Verified: well-behaved parallel clients get 32K from the graceful server, and
Linux + wrk + graceful is fine (28K on CI) — so it is a macOS × wrk interaction,
not a server bug.

Bisect (`01919ca..7e29a8a`): `67f78c6` good (27.8K) → `7b51b9a` bad (3.2K);
reverting only `closeAfterDrain` to RST on `7b51b9a` restores 27.3K.

**Fix (applied on the `audit-perf-fixes` branch):** `closeAfterDrain` is now
platform-conditional — graceful FIN close on **Linux** (keeps the no-data-drop
fix + CI throughput), fast RST close on **macOS/BSD/Windows** (restores 27K).
Benchmarks after the fix:

| Test (macOS) | Before | After fix |
|---|---|---|
| `wrk -t2 -c100 -H 'connection: close' /` | 3,276 | 26,190 |
| `wrk -t4 -c100 -H 'Connection: close' /hello` | ~3.2K | 26,869 |
| `wrk -t2 -c100 /hello` (keep-alive) | 132,101 | 132,621 |

## Performance — audit fixes themselves cause no regression

A/B on macOS (`-d:release`, CI-style `wrk -t4 -c100 -d5s /hello`), the
re-applied audit fixes vs. unmodified origin/main (`7e29a8a`):

| Test | origin/main | + audit fixes |
|---|---|---|
| single keep-alive | 139,651 | 139,824 |
| multi keep-alive | 137,798 | 137,871 |
| multi close (with the platform fix) | 3,276 | 26,869 |

The audit fixes are pure hardening and do not slow the request path.

## Round 2 — follow-ups (fixed, see plans/audit-round2.md)

| Item | Fix |
|---|---|
| Configurable size backstop | `HttpServer.maxStreamBodySize` / `HttpParser.maxStreamBodySize` lower the 512 MB hard cap when `maxBodySize == 0`; README production-config section added |
| WS post-upgrade idle/read timeout | `WsConnection.lastActive/idleTimer/idleTimeoutMs`, re-armed after each frame; `WsServer.idleTimeoutMs*` + `HttpServer.wsIdleTimeoutMs*`; silent upgraded conns are closed |
| `parseRange` strictness | trailing garbage / second range after the end number → 416; trailing OWS tolerated |
| UDP empty-send | `send`/`sendTo` return 0 for empty payloads (no `unsafeAddr data[0]`) |
| `WsServer.close()` | closes active connections (fires `onClose`, cancels idle timers) instead of only clearing tables |
| Strict request line | empty request-target, non-digit version, trailing garbage after `HTTP/x.y` → 400 |
| **SSE2 `\r\n` boundary bug** | `findCRLFSse2`/`findDoubleCRLFSse2` missed a `\r\n` spanning the 16-byte chunk boundary and could return a *later* match; a bounded scalar prefix scan now guarantees the earliest match (broke pipelining / stricter request-line parsing) |
| Windows junction escape | `resolveReal` now uses `GetFinalPathNameByHandleW` (via new `proto/winpath.nim`) to resolve junctions/symlinks; `when defined(windows)` junction regression test for the windows CI |

Verification: full powpow suite, audit harness, and the smuggler differential
(1161 requests, 0 discrepancies) all green; macOS keep-alive ~136K req/s,
`Connection: close` ~24-26K req/s.

## How to re-run

```sh
# multipart unit + security tests
nim c -r multipart/tests/test1.nim
nim c -r multipart/tests/test_security.nim

# powpow tests
for f in powpow/tests/test_*.nim; do nim c -r "$f"; done

# audit harness (security regressions)
for f in powpow/audit/*.nim; do nim c -r "$f"; done
```
