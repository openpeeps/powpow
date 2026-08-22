---
title: Overview
description: "What powpow is, its design philosophy, architecture and the complete feature matrix."
keywords: ["powpow", "overview", "architecture", "features", "nim"]
---

# Overview

powpow is a high-performance, event notification library for Nim. It provides a
low-level event loop and timer wheel, as well as higher-level abstractions for
building TCP, UDP, HTTP/1.1 and WebSocket servers. It is designed to be minimal
and efficient, with a focus on low-latency event handling and minimal overhead,
providing a solid foundation for high-performance networked applications in Nim.

It is also used as a networking backend by
[Supranim](https://github.com/supranim/supranim) — switch on `--features:powpow`
when compiling a Supranim app.

> [!WARNING]
> The library is not production-ready yet and may contain bugs and security
> vulnerabilities. It has been tested on Linux and macOS, but may not work on all
> platforms. See [security](security.md) for the hardening already in place.

## Design philosophy

- **Low-level, minimal, high-performance.** powpow does not ship a router,
  template engine or ORM. It gives you an event loop, sockets and protocol
  parsers, and lets you (or a framework) build the rest on top.
- **Bring-your-own-router.** The HTTP server exposes an
  `OnRequestCallback` and leaves routing entirely to the caller
  (see [HTTP server](http/server.md)).
- **Zero-copy where it counts.** Request fields are materialized lazily from
  byte offsets; files are sent with `sendfile`; responses can be streamed.
- **Platform-native event notification.** Built on top of `epoll` (Linux),
  `kqueue` (BSD, macOS) and `IOCP` (Windows), with a `poll` fallback — plus an
  opt-in Linux **io_uring** backend ([guide](io_uring.md)) that drives
  everything through submission/completion ops instead of readiness events.

## Architecture

```
                     ┌──────────────────────────────┐
                     │         powpow.nim           │  (aggregate entry, re-exports)
                     └──────┬──────────┬────────────┘
                ┌───────────┴──┐   ┌────┴─────────────┐
                │     loop     │   │     platform     │
                │  timer wheel │   │ epoll|kqueue|    │
                │  defer/idle  │   │ poll|iocp        │
                └───┬──────────┘   └──────────────────┘
        ┌───────────┼──────────────┐
        │           │              │
   ┌────┴────┐  ┌───┴────┐   ┌─────┴─────┐
   │ signal  │  │  net   │   │  proto    │
   │relay+OS │  │tcp udp │   │http ws    │
   │ signals │  │dns tls │   │httpserver │
   └─────────┘  └────────┘   │multithread│
                             │ratelimit  │
                             └───────────┘
```

The aggregate module `src/powpow.nim` re-exports:

- `types` — core shared types
- `platform` — the active I/O backend (except `close`, which lives on `Loop`)
- `loop` — the event loop
- `net` — TCP, UDP, DNS, TLS, socket helpers, raw-fd streams
- `proto` — HTTP, WebSocket, multi-threaded server, rate limiter
- `signal` — the signal relay and OS signal handling
- `fswatch` — file system monitoring
- `stream` — raw-fd streaming (`IoStream`, re-exported via `net`)

## Feature matrix

| Area | Status |
|---|---|
| Core event loop (`loop.nim`) | Done — single-threaded reactor, 4-level timer wheel, deferred/idle/observer hooks, thread-safe `postToLoop`/`stop` |
| TCP networking (`net/tcp.nim`) | Done — non-blocking server/client, connection pooling, corking, `sendv`, zero-copy file send, UDS, `closeAfterDrain` |
| UDP networking (`net/udp.nim`) | Done — bound and connected sockets |
| Async DNS (`net/dns.nim`) | Done — in-loop resolver, `/etc/hosts` + `resolv.conf`, A/AAAA, TTL cache |
| OS signals (`signal.nim`) | Done — signalfd (Linux), self-pipe (macOS/BSD/POSIX), Ctrl+C (Windows) |
| File system watching (`fswatch.nim`) | Done — `kqueue` (macOS/BSD), `inotify` (Linux); Windows not yet implemented |
| Raw-fd streaming (`stream.nim`) | Done — `IoStream` for pipes/socketpair/UDS/IPC; edge-triggered drain, write buffering, read backpressure; Windows not yet implemented |
| HTTP/1.1 parser (`proto/http.nim`) | Done — incremental zero-copy, chunked, streaming, multipart |
| HTTP server (`proto/httpserver.nim`) | Done — own-router design, static files, Range/conditional requests, pipelining |
| WebSocket (`proto/ws.nim`) | Done — RFC 6455, standalone + upgrade, deflate |
| Multi-threaded HTTP server (`proto/multithread.nim`) | Done — `SO_REUSEPORT`, one loop per worker |
| TLS (`net/tls.nim`) | Done — OpenSSL, implicit + upgrade (not on Windows) |
| DTLS (`net/dtls.nim`) | Done — DTLS 1.2 (RFC 6347) over the UDP backend: one socket, per-peer sessions, stateless HMAC cookie exchange, retransmission timers, idle/handshake sweepers (not on Windows) |
| SIMD scanning (`proto/simdscan.nim`) | Done — SSE2 CRLF detection with scalar fallback |
| Rate limiting (`proto/ratelimit.nim`) | Done — sliding window per IP |
| io_uring backend (`io/uring.nim`) | Done — opt-in Linux submission-based backend: full io_uring API binding, probe-based feature detection, zero-copy `SEND_ZC` + `SPLICE` file sends, registered buffers (`-d:powpowIoUring`) |
| HTTP/2 | Planned — multiplexed frames over TCP (see [performance](performance.md) for why this fits io_uring) |
| HTTP/3 (QUIC) | Not planned |

## Feature details

### Core event loop
- Single-threaded non-blocking reactor
- I/O multiplexing via kqueue (macOS/BSD), epoll (Linux), IOCP (Windows) or poll (fallback)
- **io_uring** (Linux, opt-in): the same loop driven by submission/completion
  ops — one `io_uring_enter` per iteration, op-driven sockets, kernel-timeout
  sleeps ([guide](io_uring.md))
- 4-level hierarchical timer wheel — O(1) insert/fire/cancel
- One-shot and repeating interval timers
- Deferred callbacks (executed before each I/O poll iteration)
- Idle handlers (executed when no I/O events are pending)
- Pointer-based fd watcher dispatch — zero hash-table lookups on the hot path
- Generation-counter stale event detection
- Dead watcher sweep with zombie/retired list for in-flight event safety
- Thread-safe `stop()` via eventfd (Linux) or self-pipe (macOS/BSD)
- Buffer pool for shared read buffers
- Adaptive event capacity scaling (min 64, max 4096)

### io_uring backend
- Full io_uring API binding against `linux/io_uring.h` — all opcodes, register
  ops, SQE/CQE/setup/enter flags and the ABI structs, with `io_uring_prep_*`
  style helpers; no liburing dependency
- Feature detection via `IORING_REGISTER_PROBE` (per-opcode bitmap) instead of
  kernel-version guessing
- Op-driven sockets: one-shot `ACCEPT`/`RECV`/`SEND`/`CONNECT` per connection,
  multishot accept/recv on capable kernels
- Zero-copy writes: `IORING_OP_SEND_ZC` for large payloads with
  `IORING_CQE_F_NOTIF` buffer-lifetime tracking
- Zero-copy file sends: `IORING_OP_SPLICE` (file → pipe → socket)
- Registered buffers: `IORING_REGISTER_BUFFERS` lifecycle + opt-in
  `SEND_ZC_FIXED` (`-d:powpowSendZcFixed`)

### TCP networking
- Non-blocking TCP server with connection pooling
- Non-blocking TCP client with async connect (DNS resolved on the loop)
- Edge-triggered I/O events
- Write buffering with automatic corking (TCP_CORK / TCP_NOPUSH)
- Scatter-gather writes via `writev`
- Zero-copy file send via `sendfile` (Linux `sendfile`, macOS `sendfile`, POSIX fallback)
- Graceful shutdown with close-after-drain (`closeAfterDrain`)
- Unix domain socket support (macOS/BSD/Linux)
- `SO_LINGER{0}` for fast shutdown
- Per-connection read buffer pooling

### Async DNS
- In-loop DNS resolver (RFC 1035) — no blocking `getaddrinfo`, no worker threads
- Reads `/etc/hosts` and `/etc/resolv.conf` (system resolver config)
- A + AAAA queries with A-fallback; retries with timeout/attempts
- TTL-based result cache + negative caching
- `resolveAddrAsync` for users; `connect` uses it automatically
- Numeric IP literals resolve inline (zero DNS I/O)

### OS signals
- In-process `SignalRelay` pub/sub bus (listen / listenOnce / unlisten)
- `watchOsSignal` / `watchOsSignals` deliver real OS signals through the loop
- `OsSignal` enum: SIGHUP, SIGINT, SIGQUIT, SIGUSR1/2, SIGPIPE, SIGALRM, SIGTERM,
  SIGURG, SIGCHLD, SIGIO
- Platform-native delivery: signalfd (Linux), self-pipe (macOS/BSD/POSIX),
  `SetConsoleCtrlHandler` Ctrl+C (Windows) — no global signal handlers
- Graceful shutdown on SIGINT/SIGTERM without blocking the loop

### Raw-fd streaming
- `IoStream` wraps an arbitrary non-blocking fd and drives it from the loop
- `openStream` for pipes, subprocess stdio, UDS and regular files; `newStreamPair`
  creates a full-duplex `socketpair`
- Connection-style write path: direct write drained until EAGAIN, remainder
  buffered and flushed on Write events; 32 MiB queued-write cap
- `pause`/`resume` give real read backpressure (a paused reader fills the kernel
  pipe buffer and blocks the writer)
- `close` is the single terminal transition and fires `onClose` exactly once;
  `closeAfterWrite` flushes then delivers EOF to the peer
- Platform notes: regular files work on kqueue but not epoll; Windows compiles
  the module away (IOCP is sockets-only)

### HTTP/1.1 parser
- Incremental, zero-copy parser — materialize strings lazily from byte offsets
- O(1) method dispatch via first-byte switch
- Pipelined request support
- Streaming body handling via callback
- Chunked transfer encoding
- Body streaming to file
- Multipart form data support

### HTTP server
- Implement-your-own-router — lower-level callback-based design
- `OnRequestCallback* = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.}`
- Higher-level frameworks implement routing on top of this callback
- Streaming response body
- Static file serving with MIME type detection
- Conditional requests (If-Modified-Since, If-None-Match)
- Range requests with 206 Partial Content
- Directory listing
- CORS headers
- Streaming multipart upload handling
- Pipelined request-response processing

### WebSocket
- RFC 6455 compliant
- Standalone WebSocket server mode
- HTTP upgrade from `HttpServer` routes
- Text, binary, ping/pong, and close frames
- Per-message deflate extension
- Masked frame handling

### Multi-threaded HTTP server
- `SO_REUSEPORT` kernel-level connection distribution
- One event loop + listen socket per worker thread
- Zero cross-thread communication — no single-threaded acceptor bottleneck
- Graceful shutdown via shutdown pipe

### SIMD-accelerated scanning
- SSE2-accelerated CRLF detection
- Scalar fallback for non-x86 architectures

### Platform abstraction
- `kqueue` — macOS/BSD (high-performance, edge-triggered)
- `epoll` — Linux (with eventfd wake)
- `poll` — POSIX fallback
- `iocp` — Windows (I/O Completion Ports)

### Networking common
- Platform-agnostic socket API and address resolution (IPv4 + IPv6)
- Socket options: non-blocking, `SO_REUSEADDR`, `SO_REUSEPORT`, `TCP_NODELAY`
- `sendfile` zero-copy file transmission
- Cross-platform error handling (EAGAIN, EINPROGRESS, etc.)
- Auto-initialization (WSAStartup on Windows, SIGPIPE ignore on POSIX)

## Where to go next

- [Getting started](getting-started.md)
- [Examples index](examples.md) — 19 runnable programs covering every feature
- [API reference](api/README.md)
