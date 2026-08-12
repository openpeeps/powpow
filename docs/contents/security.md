---
title: Security
description: "powpow's security hardening: timeouts, bounded buffering, upload caps, static-file safety, and the recommended production configuration."
keywords: ["powpow", "security", "hardening", "dos", "limits"]
---

# Security

A dedicated security audit was performed (`audit/REPORT.md`); its
high-priority findings are fixed and locked in by regression tests in
`tests/test_security.nim`. This page summarizes the hardening already in place.

> [!WARNING]
> The library is not production-ready. Use it, test it, and report any issues
> you find at https://github.com/openpeeps/powpow/issues.

## Hardened by default

- **Idle / read timeouts** — `readTimeoutMs` and `keepAliveMs` are enforced per
  connection, closing slowloris and idle keep-alive connections that never
  complete their requests.
- **Bounded header buffering** — an oversized header packet is rejected
  (`414`/`431`) *before* the parser grows its buffer to the packet size, so a
  hostile multi-megabyte header block cannot force a matching allocation.
- **Overflow-safe `Content-Length`** — adversarial values (e.g. `2^63`) are
  rejected instead of crashing or wrapping to a negative length, closing a
  request-smuggling/desync primitive.
- **Bounded streaming uploads** — streamed bodies (temp-file and multipart) are
  capped even with `maxBodySize = 0`, and size-limit violations reply `413`
  instead of raising an unhandled exception.
- **WebSocket frame caps** — an absolute frame-size cap applies even in
  `maxFrameSize = 0` ("unlimited") mode, preventing OOM on hostile 64-bit
  lengths and unbounded fragmented-message assembly.
- **Stack-safe response headers** — `sendFile`/`streamFile` header assembly
  grows safely; long filenames or custom headers can no longer overflow a fixed
  stack buffer.
- **Path-confusion-proof static serving** — `serveFile` requires a real path
  boundary under `fsRoot`, so a sibling directory sharing the prefix
  (e.g. `/var/www2`) can no longer be served.
- **Symlink-safe static serving** — served paths are resolved with `realpath`
  and must stay under `fsRoot`; a symlink inside the root pointing outside is
  rejected with `403`.
- **Multipart per-file limits** — `server.maxFileSize` bounds a single uploaded
  part independently of the total body cap (violations reply `413`).
- **WebSocket handshake hardening** — `handshakeTimeoutMs` closes connections
  that never complete the HTTP→WebSocket upgrade, and `maxHandshakeSessions`
  caps in-flight handshakes (handshake-stall DoS defense).
- **Strict header parsing** — obs-fold / leading-whitespace header lines are
  rejected (`400`), and `Transfer-Encoding` enables chunked framing only when
  the final token is exactly `chunked`.
- **Thread-safe rate limiter** — `RateLimiter` guards its bucket table with a
  lock, so it can be shared across multi-threaded server workers.
- **TLS reflection guards** — the TLS `sendv` coalesce buffer is capped
  (1 MB), so an attacker-controlled response echoed over TLS cannot force an
  arbitrarily large allocation.

## Recommended production configuration

For publicly reachable endpoints, set explicit caps instead of relying on the
defaults (the `maxBodySize = 0` backstop is `MaxStreamBodySize`):

```nim
let server = newHttpServer(loop)
server.maxBodySize    = 50 * 1024 * 1024      # 50 MB total request body
server.maxStreamBodySize = 64 * 1024 * 1024   # hard cap even when maxBodySize=0
server.maxFileSize    = 10 * 1024 * 1024      # 10 MB per uploaded file
server.maxFieldSize   = 64 * 1024             # 64 KB per text field
server.maxConnections = 4096                  # cap concurrent connections
server.maxPipelineDepth = 4                   # cap pipelined requests
server.readTimeoutMs  = 5_000                 # slowloris / partial-request close
server.setKeepAliveTimeout(5_000)             # idle keep-alive close
```

The same caps apply to the standalone `WsServer` via `maxFrameSize`,
`handshakeTimeoutMs`, `maxHandshakeSessions`, and (once enabled) a
post-upgrade `idleTimeoutMs`.

## Smuggler

[Smuggler](https://github.com/openpeeps/smuggler) is a grammar-based HTTP/1.x
request-smuggling fuzzer built for this library: it generates and mutates
requests from a context-free grammar, detects CL/TE desyncs with an in-process
oracle, and drives live servers with the two-request response-pairing technique.

```bash
nimble testSmuggler                       # in-process + differential suites
smuggler -g tests/fuzz/request-line.cfg -t 127.0.0.1:9000 -n 1000
```

## Security roadmap

- [ ] Coverage-guided fuzzing of the HTTP / WebSocket / multipart parsers
      (libFuzzer & nim-drchaos adapters in `smuggler`)
- [ ] ASan/UBSan sanitizer build wired into CI
- [ ] Stream body bytes before first-packet buffering (avoid peak RAM on large
      single-packet uploads)
- [x] Multipart per-file size limits wired to server configuration
- [x] Symlink-safe static serving (realpath checks)
- [x] WebSocket handshake timeout and handshake-session bound
- [x] Rate-limiter thread-safety in multi-threaded mode
- [x] Strict header parsing (reject obs-fold/leading-whitespace header lines,
      non-`chunked` `Transfer-Encoding` tokens)
- [x] Response-reflection guards for large attacker-controlled echoes under TLS

## Related docs

- [Testing](testing.md) — how the hardening is verified
- [Static files](http/static-files.md) — path/symlink safety details
- [Multipart](http/multipart.md) — upload caps
- [WebSocket](websocket.md) — frame/handshake caps
