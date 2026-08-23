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

let srv = newHttpServer(numThreads = 0)   # 0 = one per CPU core
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

- **`RateLimiter` is thread-safe**: its bucket table is lock-guarded, so a
  single limiter can be shared across workers
  ([rate limiting](http/rate-limiting.md), `tests/test_ratelimit_threads.nim`).
- **`OnRequestCallback` must be `{.gcsafe.}`**: the handler signature enforces
  it, since it runs on multiple threads.
- **`postToLoop`** is the safe way to get work onto a specific loop from another
  thread ([event loop](core/event-loop.md)); the loop's `stop()` is also
  thread-safe.
- Each worker runs its own loop; don't share loop-owned state across loops
  without explicit synchronization.

## Thread pool: `ThreadPool`

A self-managed worker pool for CPU-bound or blocking work that must not stall
an event loop. It owns `N` persistent workers plus one dispatch thread running a
private event loop. Job results are delivered on that loop, so every callback
fires serialized on the same thread.

```nim
let tp = newThreadPool(size = 4)

discard tp.submitWork(
  job = proc(): string {.closure.} = heavyComputation(),
  cb  = proc(res: string) {.closure.} =
    echo "got ", res.len, " bytes")          # runs on tp's dispatch thread

closeThreadPool(tp)       # graceful: drain queued jobs, then tear down
```

- `shutdownThreadPool(tp)` is the immediate variant: queued-but-unstarted jobs
  are discarded (their callbacks never fire); in-flight jobs finish naturally.
- `submitWork` returns `false` once either shutdown began.
- A raising job delivers `onError(err)` instead of `cb`; with `onError == nil`
  the failure is swallowed and the pool stays healthy.
- Callbacks run on the dispatch thread, so synchronize anything they share
  with other threads. Host extra timers/sockets via `tp.getLoop()` (register
  from the dispatch thread, e.g. inside a callback).
- Requires threads enabled; `-d:powpowNoThreads` compiles stubs that raise.

Runnable test-style examples: `tests/test_threadpool.nim`.

## How it compares to other Nim thread pools

Nim's built-in `std/threadpool` (`spawn` / `FlowVar`) is **deprecated**; its
own documentation points at three community packages: `taskpools`, `weave` and
`malebolgia`. All four are excellent at what they were designed for, but none targets
*event-loop-integrated* execution, which is the gap powpow's `ThreadPool`
fills.

### The landscape

- **`std/threadpool`** (stdlib): a global FIFO queue; `spawn` returns a
  `FlowVar` that the caller blocks on with `^`. Deprecated upstream.
- **`taskpools`**: a lightweight work-stealing fork/join pool. Tasks are
  submitted into scoped parallel regions and joined with blocking `sync` /
  `waitForAll` calls.
- **`weave`**: an HPC-grade data-flow runtime with per-worker work-stealing
  deques, lazy futures and structured `parallelFor` constructs. Built for
  numeric throughput on many cores, NUMA-aware.
- **`malebolgia`**: Araq's structured-concurrency pool. A `Master` guards an
  `awaitAll` block; results are written into caller-provided storage, and
  exceptions are aggregated onto the master. Backed by `std/tasks` +
  `std/isolation`.

| | std/threadpool | taskpools | weave | malebolgia | **powpow** |
|---|---|---|---|---|---|
| Status | deprecated | maintained | maintained | maintained | built-in |
| Result style | `FlowVar` (`^`) | blocking sync | lazy futures | caller storage + `awaitAll` | **callback on a loop thread** |
| Blocks the caller | yes (`^`) | yes (at join) | yes (at join) | yes (`awaitAll`) | **never** |
| Lifecycle | global pool | scoped regions | scoped/global | scoped block | **long-lived service pool** |
| Runtime closures as jobs | limited | via ptr buffers | limited | isolation-constrained | **generic `[T]`, managed types OK** |
| Work stealing | no | yes | yes (HPC-grade) | no | no (FIFO) |
| Event-loop integration | none | none | none | none | **private `Loop` + `getLoop()` hosting** |
| Shutdown control | panic stop | sync-based | sync-based | cancel / timeout | **graceful drain AND discard** |

### Where powpow's thread pool wins

- **It never blocks the calling thread.** Every alternative requires a join,
  a `FlowVar` read or an `awaitAll` barrier, all fatal inside an event loop
  iteration. `submitWork` is fire-and-forget; results arrive as callbacks.
- **Callbacks are serialized for you.** All results fire on one dispatch
  thread, so state they touch needs no locks against other completions. With
  N workers invoking user code directly, you would need your own locking.
- **Long-lived service semantics.** Submit work at any time over the
  program's lifetime; malebolgia/taskpools model bounded parallel regions.
- **Generic managed results without pointer marshalling.**
  `submitWork[T]` moves strings, seqs and fresh refs between threads under
  single-ownership rules, with no `ptr`/`isolate` gymnastics required from
  users.
- **Dual shutdown semantics.** `closeThreadPool` drains everything;
  `shutdownThreadPool` discards queued work for fast teardown. Both are
  idempotent.
- **Zero extra dependencies**: raw threads, condvars and powpow's own loop.
  The ORC single-owner discipline it relies on is documented in the module
  header and regression-tested (`tests/test_threadpool.nim`).

### When to prefer the alternatives

Credibility cuts both ways. Powpow's pool optimizes for event-driven
services, not scheduling throughput:

- Numeric crunching across many cores where work-stealing pays for itself →
  `weave` (or `taskpools` for lighter builds).
- Structured fork/join batch blocks ("run these 10k computations, wait") →
  `malebolgia`.
- Also expect ~1 heartbeat (10 ms) worst-case delivery latency and simple
  FIFO ordering: features, not bugs, for service work, but not HPC
  scheduling.

## When to use which

| Need | Use |
|---|---|
| One service, simplest model | `newHttpServer(loop)` on a single loop |
| Multiple services, one process | several servers on a shared `Loop` |
| CPU-bound throughput | `newHttpServer` + `--threads:on` |
| Blocking/CPU-bound work off a live loop | `newThreadPool` + `submitWork` |
| HPC data-parallel number crunching | `weave` / `taskpools` (external) |
| Structured fork/join batch blocks | `malebolgia` (external) |

## API reference

Full signatures: [multithread API](api/multithread.md). Related:
[server](http/server.md), [event loop](core/event-loop.md).
