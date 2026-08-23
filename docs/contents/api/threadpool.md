---
title: ThreadPool
description: "The ThreadPool API: self-managed workers with callback delivery on a private event loop."
keywords: ["powpow", "api", "threadpool", "thread pool", "workers", "jobs"]
---

# ThreadPool

A self-managed worker pool built on raw threads and condvars, with one
dedicated dispatch thread running a private event loop. Jobs execute on
workers; results come back as callbacks on the pool's own loop, serialized
against each other. No high-level parallelism APIs are involved.

Source: `src/powpow/threadpool.nim`. Guide:
[concurrency](../concurrency.md).

## Types

```nim
ThreadPool* = ref object
  ## N persistent workers plus one dispatch thread running the pool's
  ## private event loop.
ThreadPoolError* = object of CatchableError
```

`HeartbeatMs* = 10` is the dispatch-loop keep-alive cadence. It also bounds
the worst-case result delivery latency when no other loop activity forces
poll iterations.

## Procs

```nim
proc newThreadPool*(size: int = 4): ThreadPool
proc getLoop*(pool: ThreadPool): Loop
proc submitWork*[T](pool: ThreadPool;
                    job: proc (): T {.closure.};
                    cb: proc (res: T) {.closure.};
                    onError: proc (err: ref CatchableError) {.closure.} = nil): bool {.discardable.}
proc closeThreadPool*(pool: ThreadPool)
proc shutdownThreadPool*(pool: ThreadPool)
```

### `newThreadPool(size = 4)`

Starts `size` worker threads plus one dispatch thread. The pool owns its
private event loop for the rest of its life; obtain it with `getLoop`.

### `submitWork[T]`

Runs `job` on a worker. When it returns a value, `cb(res)` fires on the
dispatch thread. When the job raises, `onError(err)` fires instead and `cb`
is skipped. With `onError == nil` failures are swallowed and the pool stays
healthy.

Returns `true` if the job was queued, `false` once either shutdown began;
in that case neither callback fires. The result is discardable.

### `getLoop`

Returns the pool's private event loop. Register timers or watchers on it
from the dispatch thread only (for example from inside a callback), never
from foreign threads.

### `closeThreadPool` and `shutdownThreadPool`

Both stop accepting new work and join all threads; both are idempotent.

| Proc | Queued but unstarted jobs | In-flight jobs | Results |
|---|---|---|---|
| `closeThreadPool` | drained normally | finish naturally | all delivered |
| `shutdownThreadPool` | discarded silently | finish naturally | in-flight only |

After either call, further `submitWork` invocations return `false`.

## Examples

### Basic submission

```nim
let tp = newThreadPool(size = 4)

discard tp.submitWork(
  job = proc(): string {.closure.} = readFile("payload.bin"),
  cb  = proc(res: string) {.closure.} =
    echo "read ", res.len, " bytes")     # runs on tp's dispatch thread

closeThreadPool(tp)                      # graceful drain on app exit
```

### Handling job failures

```nim
discard tp.submitWork(
  job = proc(): int {.closure.} =
    if not fileExists("cfg.txt"):
      raise newException(IOError, "missing cfg.txt")
    result = 42,
  cb = proc(res: int) {.closure.} =
    echo "answer: ", res,
  onError = proc(err: ref CatchableError) {.closure.} =
    echo "job failed: ", err.msg)
```

The callback pair never throws into the pool. An unhandled failure without
an `onError` handler is dropped; workers keep serving subsequent jobs.

### Hosting timers on the pool's loop

```nim
# Inside any callback (dispatch thread):
let timerId = tp.getLoop().addTimer(5_000) do () {.closure.}:
  echo "periodic tick alongside result delivery"
# cancelTimer(tp.getLoop(), timerId) to stop it
```

This turns the pool into a small execution environment: results, timeouts
and socket events can share one thread.

### Graceful drain versus fast teardown

```nim
closeThreadPool(tp)       # wait: queue drains, every callback fires
shutdownThreadPool(tp)    # now: pending jobs dropped, in-flight finish
```

Use `shutdownThreadPool` when latency at exit matters more than completing
already-queued work (for instance during process teardown).

## Threading contract

- All callbacks execute on the pool's dispatch thread, serialized against
  each other.
- Values returned by jobs move between threads under single-ownership rules.
  Ints, strings, seqs and freshly created refs are fine. Do not share the
  same object between a callback and another thread without your own
  synchronization.
- Host timers or watchers on `getLoop()` from the dispatch thread only.

Under ARC/ORC, reference-count operations are not atomic. The module follows
strict single-owner move semantics for everything crossing a thread boundary:
workers never touch shared managed state, and each task's closures travel
submitter, worker, dispatcher as a box whose ownership moves exactly once per
hop. This design avoids releasing managed memory from scheduler-dependent
threads, which corrupts ORC's per-thread cycle registry. Details live in the
module header comment.

Builds with `-d:powpowNoThreads` compile stubs whose entry points raise
`ThreadPoolError`.

## Related

- [concurrency](../concurrency.md): threading model overview and comparison
  with std/threadpool, taskpools, weave and malebolgia
- [event loop](../core/event-loop.md): the Loop the dispatch thread runs
