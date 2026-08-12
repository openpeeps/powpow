---
title: Concurrency
description: "Multi-threaded HTTP servers with SO_REUSEPORT, one event loop per worker, and thread-safety notes."
keywords: ["powpow", "concurrency", "multithread", "threads", "reuseport"]
---

# Concurrency

powpow's core is a **single-threaded** event loop, but it ships a
**multi-threaded HTTP server** built on `SO_REUSEPORT`: the kernel load-balances
incoming connections across N worker threads, each running its own event loop
and listen socket. There is no cross-thread acceptor bottleneck and zero
shared-lock contention on the hot path.

Runnable example: [`examples/httpserver_threads.nim`](../examples/httpserver_threads.nim).

## Multi-threaded HTTP server

```nim
import powpow

proc handler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  res.send("worker handling this request")

let srv = newMultiThreadHttpServer(numThreads = 0)   # 0 = one per CPU core
srv.start(handler, "0.0.0.0", Port(9000))
```

`numThreads = 0` (default) spawns one loop per CPU core. Compile with
`--threads:on`:

```bash
nim c -r --threads:on examples/httpserver_threads.nim
```

`MultiThreadHttpServer` has a public `numThreads` field. `listen(address, port)`
pre-binds before `start`; `close()` tears the workers down gracefully via a
shutdown pipe.

## Thread safety notes

- **`RateLimiter` is thread-safe** — its bucket table is lock-guarded, so a
  single limiter can be shared across workers
  ([rate limiting](http/rate-limiting.md), `tests/test_ratelimit_threads.nim`).
- **`OnRequestCallback` must be `{.gcsafe.}`** — the handler signature enforces
  it, since it runs on multiple threads.
- **`postToLoop`** is the safe way to get work onto a specific loop from another
  thread ([event loop](core/event-loop.md)); the loop's `stop()` is also
  thread-safe.
- Each worker runs its own loop; don't share loop-owned state across loops
  without explicit synchronization.

## When to use which

| Need | Use |
|---|---|
| One service, simplest model | `newHttpServer(loop)` on a single loop |
| Multiple services, one process | several servers on a shared `Loop` |
| CPU-bound throughput | `newMultiThreadHttpServer` + `--threads:on` |

## API reference

Full signatures: [multithread API](api/multithread.md). Related:
[server](http/server.md), [event loop](core/event-loop.md).
