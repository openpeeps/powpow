---
title: Event loop
description: "The powpow Loop: timers, deferred and idle hooks, fd events, observers, buffer pooling, and the platform backends."
keywords: ["powpow", "event loop", "timers", "kqueue", "epoll", "loop"]
---

# Event loop

The `Loop` is the heart of powpow. Everything — TCP, UDP, HTTP, WebSocket,
DNS, signals, file watching, timers — is driven by a single `Loop`. It is a
single-threaded non-blocking reactor over the platform's native multiplexer
(`kqueue` on macOS/BSD, `epoll` on Linux, `IOCP` on Windows, `poll` as a
fallback).

Runnable example: [`examples/timers_scheduler.nim`](../../examples/timers_scheduler.nim).

## Creating a loop

```nim
let loop = newLoop()
```

Most higher-level helpers can create their own loop for you (`newHttpServer()`,
`newWsServer()`), but passing an explicit `Loop` is how you compose several
services — HTTP, DNS, signals, timers — into one process and one thread.

## The main loop

```nim
loop.run()          # blocks forever, dispatching events
loop.runOnce()      # run a single iteration of the poll loop
loop.poll(timeoutMs = -1)
loop.stop()         # thread-safe: wake the loop and stop it
loop.isRunning()    # is the loop still active?
```

`stop()` is thread-safe (via `eventfd` on Linux, a self-pipe on macOS/BSD), so
another thread or a signal handler can ask the loop to exit.

## Monotonic clock

```nim
let now = monoMs()      # int64 milliseconds since an arbitrary epoch
```

## Timers and the timer wheel

Timers are backed by a 4-level hierarchical timer wheel with O(1)
insert/fire/cancel.

```nim
proc onTimer(id: int) = echo "fired"

let oneShot  = loop.addTimer(1000, onTimer)      # fire once after 1s
let interval = loop.addInterval(500, onTimer)    # fire every 500ms

loop.cancelTimer(oneShot)                        # never fire
loop.pauseTimer(interval)                        # pause (keeps remaining time)
loop.resumeTimer(interval)                       # resume

loop.timerCount()                                # number of active timers
```

Timer callbacks receive the timer's id (`TimerId`, a distinct `int`).

## Deferred callbacks

Run before the next poll iteration — the "do this as soon as the current event
handling unwinds" queue.

```nim
loop.deferCall(proc() = echo "runs before the next poll")
```

## Cross-thread posting

`postToLoop` is the safe way to get work onto the loop from another thread.

```nim
# from any thread:
loop.postToLoop(proc() = echo "runs on the loop thread")
```

This is the primitive the thread-safety tests and multi-threaded server rely on.

## Idle handlers

Run when the loop has no I/O events to process.

```nim
let idleId = loop.addIdle(proc() = echo "nothing to do")
loop.removeIdle(idleId)
```

## Observers

Watch a `uint64` value for changes and get a callback.

```nim
var counter: uint64
let obs = loop.observe(addr counter, proc(value: uint64) = echo value)
counter += 1                     # next loop tick notices and fires the observer
loop.cancelObserver(obs)
```

## File descriptor events

`register` wires an fd into the loop with a callback for a set of events.
This is the raw API the higher-level net modules are built on.

```nim
import powpow

proc onFd(fd: int, events: set[EventType]) =
  if Read in events:
    # read from fd, then re-arm if you are edge-triggered
    discard

loop.register(fd, {Read, Error, Hup}, onFd, edgeTriggered = true)
loop.modify(fd, {Read, Write, Error, Hup})     # change the interest set
loop.unregister(fd)
```

`EventType` is `Read`, `Write`, `Error` or `Hup`. Watchers are dispatched by
pointer with generation-counter stale-event detection, so a callback is never
invoked for an fd that was unregistered and reused.

## Cleanup hooks

```nim
loop.addCleanup(proc() = echo "runs when the loop closes")
```

`loop.close()` runs all cleanup hooks (the DNS resolver, the signal source and
the file watchers register their own) and closes the platform backend.

## Public `Loop` fields

- `platform*: Platform` — the active I/O backend
- `bufPool*: seq[ptr UncheckedArray[byte]]` — the shared read-buffer pool
- `dns*: ref RootObj` — the DNS resolver, when created
- `sigSource*: ref RootObj` — the OS-signal source, when created
- `closed*: bool`

## Buffer pooling

The loop carries a pool of shared read buffers used by the TCP layer:

```nim
let buf = loop.acquireBuf()        # ptr UncheckedArray[byte]
# ... read into it ...
loop.releaseBuf(buf)
```

`DefaultBufSize` is 4096 bytes.

## Backends

The platform layer is selected at compile time by `platform.nim`:

| Platform | Backend |
|---|---|
| Linux | `epoll` (with eventfd wake) |
| macOS / BSD | `kqueue` (edge-triggered) |
| Windows | `iocp` |
| anything else | `poll` |

Every backend exposes the same surface: `Platform.init`, `add`, `remove`,
`modify`, `wake`, `poll`, `close`, plus the `Platform`/`PlatformEvent` types.
You almost never touch these directly — see the [platform API page](../api/platform.md).

## API reference

Full signatures: [loop API](../api/loop.md). Underlying types: [types API](../api/types.md).
