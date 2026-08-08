# Audit Round 2 — Remaining follow-ups + quick wins

Status: approved (2026-08-08). Companion report: `audit/REPORT.md`.

## 1. Configurable size backstop + docs

- Expose `server.maxStreamBodySize` (and mirror on the parser) so operators can
  lower the 512 MB hard cap; keep 512 MB as the default.
- Add a "recommended production configuration" section to the powpow README:
  `maxBodySize`, `maxFileSize`, `maxFieldSize`, `maxStreamBodySize`,
  `maxConnections`, `maxPipelineDepth`, `readTimeoutMs`, `keepAliveMs`, and WS
  `idleTimeoutMs`.

## 2. Windows symlink/junction escape (`resolveReal`, httpserver.nim:1077)

- POSIX already resolves symlinks via `realpath`; Windows falls back to
  `absolutePath` (no symlink/junction resolution) → a junction inside `fsRoot`
  pointing outside is served by both `serveStatic` and `serveFile`.
- Fix: new `when defined(windows)` branch in `resolveReal`:
  `CreateFileW(..., OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS)` +
  `GetFinalPathNameByHandleW` (small `importc` over `std/winlean`), strip the
  `\\?\` prefix, fall back to `absolutePath` on failure.
- Add a `when defined(windows)` junction-based regression test (junctions need
  no admin) exercised by the existing windows-latest CI job. Cannot be
  runtime-tested on macOS — validated by CI only.

## 3. WebSocket post-upgrade idle/read timeout (ws.nim)

- `WsConnection`: add `lastActive: int64` (bumped in `parseWsFrames` and at
  creation), `idleTimer: TimerId`, `idleTimeoutMs: int`.
- Re-arm a one-shot loop timer after each `parseWsFrames` in both fd callbacks
  (`WsServer.listen` and `websocketUpgrade`); the timer closes the connection
  when `now - lastActive > idleTimeoutMs` (guarded by `conn.state`).
- `WsServer.idleTimeoutMs*` (0 = disabled, default 0 → non-breaking) and
  `HttpServer.wsIdleTimeoutMs*` read at upgrade time.
- Cancel the idle timer on `closeWs` and close paths.

## 4. `parseRange` strictness (httpserver.nim:99)

- After parsing the end number, skip trailing OWS then require end-of-value;
  otherwise return 416 (rejects `bytes=0-5garbage` and unsupported multi-range
  `bytes=0-1,5-6`).

## 5. UDP empty-send (udp.nim:42-68)

- `if data.len == 0: return 0` in `send`/`sendTo` (avoids `unsafeAddr data[0]`
  on an empty payload).

## 6. Quick wins

- `WsServer.close()` (ws.nim:760): close each active WS connection (fires
  `onClose`) instead of only clearing the tables.
- `parseRequestLine`: reject an empty path and trailing garbage after the HTTP
  version token.

## Tests / verification

- New runnable tests in `audit/` for items 3, 4, 5, 6; `when defined(windows)`
  gated test for item 2.
- Re-run multipart + powpow suites and the smuggler differential (keep 0
  failures / 0 discrepancies).
- Update `audit/REPORT.md` and the `security-improvements.md` status block to
  reflect round 2.
