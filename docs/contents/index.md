---
title: powpow
description: "A high-performance, event notification library for Nim: an event loop, TCP/UDP, HTTP/1.1, WebSocket, TLS and more."
keywords: ["powpow", "nim", "networking", "event loop", "http", "websocket"]
---

# 💥 powpow

A **high-performance event notification library for Nim**. powpow provides a
low-level event loop and timer wheel, plus higher-level abstractions for
building TCP, UDP, HTTP/1.1, WebSocket and multi-threaded servers — built on top
of `epoll` (Linux), `kqueue` (BSD, macOS) and `IOCP` (Windows).

```bash
nimble install powpow
```

> [!WARNING]
> The library is not production-ready yet and may contain bugs and security
> vulnerabilities. It has been tested on Linux and macOS. **Use it, test it, and
> do not hesitate to report any issues you find!**

## Key features

- **Event loop** — single-threaded reactor, 4-level timer wheel, deferred/idle
  hooks, thread-safe `postToLoop`
- **TCP & UDP** — non-blocking servers and clients, connection pooling,
  zero-copy `sendfile`, Unix domain sockets
- **HTTP/1.1** — incremental zero-copy parser, chunked and streaming bodies,
  multipart uploads, static file serving with Range support
- **WebSocket** — RFC 6455, standalone and HTTP-upgrade modes
- **TLS** — OpenSSL, implicit and STARTTLS-style upgrades
- **Async DNS** — in-loop resolver, no blocking `getaddrinfo`
- **Multi-threaded** — `SO_REUSEPORT` workers, one event loop per core
- **SIMD** — SSE2-accelerated HTTP message scanning

## Getting started

@overview.md

@getting-started.md

@examples.md

## Guides

@core/event-loop.md

@net/tcp.md

@http/server.md

@websocket.md

## Reference

@api/README.md

@security.md

@performance.md

@testing.md
