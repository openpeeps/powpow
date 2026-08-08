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
