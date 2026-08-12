---
title: multithread
description: "The multi-threaded HTTP server API: newMultiThreadHttpServer, listen, start and close."
keywords: ["powpow", "api", "multithread", "reuseport", "threads"]
---

# multithread

Multi-threaded HTTP server (`SO_REUSEPORT`, one event loop per worker).
Source: `src/powpow/proto/multithread.nim`. POSIX-only.
Guide: [Concurrency](../concurrency.md).

## Type

```nim
MultiThreadHttpServer* = ref object
  numThreads*: int
```

## Procs

```nim
proc newMultiThreadHttpServer*(numThreads: int = 0): MultiThreadHttpServer
proc listen*(srv: MultiThreadHttpServer, address: string, port: int)
proc start*(srv: MultiThreadHttpServer, cb: OnRequestCallback, address: string, port: int)
proc close*(srv: MultiThreadHttpServer)
```

`numThreads = 0` spawns one event loop per CPU core. Compile with
`--threads:on`.

## Related

- [httpserver](httpserver.md) — `OnRequestCallback`, the handler signature
