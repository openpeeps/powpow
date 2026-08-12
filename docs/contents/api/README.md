---
title: API reference
description: "Per-module API reference pages: types, constants and every exported proc signature, organized by module."
keywords: ["powpow", "api", "reference", "signatures", "types"]
---

# API reference

These pages document the public API surface of each module — types, constants,
and every exported proc with its signature. They are **usage-oriented summaries**:
full, always-current docs are generated from the source by `nim doc` and
published to the live site:

- [https://openpeeps.github.io/powpow](https://openpeeps.github.io/powpow) — generated API reference (gh-pages, from `.github/workflows/docs.yml`)

The aggregate entry module is `src/powpow.nim`, which re-exports `types`,
`platform` (except `close`), `loop`, `net`, `proto`, `signal` and `fswatch` —
so `import powpow` brings in everything below.

## Core

- [types](types.md) — `EventType`, callbacks, `TimerId`
- [loop](loop.md) — the event loop, timers, fd events
- [signal](signal.md) — `SignalRelay` bus and OS signals
- [fswatch](fswatch.md) — file system watching
- [stream](stream.md) — raw-fd streaming (`IoStream`)
- [dns](dns.md) — the async resolver

## Networking

- [common](common.md) — sockets, resolution, sendfile
- [tcp](tcp.md) — TCP server/client
- [udp](udp.md) — UDP sockets
- [tls](tls.md) — OpenSSL TLS layer
- [tlsapi](tlsapi.md) — raw OpenSSL bindings

## Protocols

- [http](http.md) — the HTTP/1.1 parser and `HttpRequest`
- [httpserver](httpserver.md) — the HTTP server and `HttpResponse`
- [ws](ws.md) — WebSocket
- [ratelimit](ratelimit.md) — the rate limiter
- [multithread](multithread.md) — the multi-threaded HTTP server
- [simdscan](simdscan.md) — SIMD CRLF scanning

## Platform

- [platform](platform.md) — the I/O multiplexer backends (epoll / kqueue / poll / iocp)

## Notes

- `SignalRelay`, `WsFrameParser` and `Platform` internals are not exported as
  types but appear in exported signatures — treat them as opaque handles.
- `Loop.dns` and `Loop.sigSource` are opaque `ref RootObj` slots owned by the
  resolver and signal source.
- On POSIX, `net/common.nim` re-exports `std/posix`, so the raw socket syscalls
  are part of the accessible surface.
