---
title: loop
description: "The Loop API: timers, fd events, deferred/idle hooks, observers and lifecycle procs."
keywords: ["powpow", "api", "loop", "timers", "event loop"]
---

# loop

The core event loop and timer wheel. Source: `src/powpow/loop.nim`.
Guide: [Event loop](../core/event-loop.md).

## Types

```nim
FdWatcher* = ref object
  fd*: int
  events*: set[EventType]
  callback*: FdCallback
  edgeTriggered*: bool

Observer* = ref object
  varPtr*: ptr uint64
  cb*: ObserverCallback

Loop* = ref object
  platform*: Platform
  bufPool*: seq[ptr UncheckedArray[byte]]
  dns*: ref RootObj
  sigSource*: ref RootObj
  closed*: bool
```

## Procs

```nim
proc monoMs*(): int64 {.inline.}                    # monotonic ms clock

proc newLoop*(): Loop

# lifecycle
proc addCleanup*(loop: Loop; cb: Callback)
proc close*(loop: Loop)
proc stop*(loop: Loop)
proc isRunning*(loop: Loop): bool
proc run*(loop: Loop)
proc runOnce*(loop: Loop)
proc poll*(loop: Loop, timeoutMs: int = -1) {.inline.}

# fd events
proc register*(loop: Loop, fd: int, events: set[EventType], callback: FdCallback, edgeTriggered = false)
proc unregister*(loop: Loop, fd: int)
proc unregisterFd*(loop: Loop, fd: int)
proc modify*(loop: Loop, fd: int, events: set[EventType]) {.inline.}

# deferred / cross-thread
proc deferCall*(loop: Loop, cb: Callback) {.inline.}
proc postToLoop*(loop: Loop, cb: Callback)          # thread-safe

# timers (timer wheel)
proc addTimer*(loop: Loop, delayMs: int, callback: TimerCallback): TimerId
proc addInterval*(loop: Loop, intervalMs: int, callback: TimerCallback): TimerId
proc cancelTimer*(loop: Loop; id: TimerId)
proc pauseTimer*(loop: Loop; id: TimerId)
proc resumeTimer*(loop: Loop; id: TimerId)
proc timerCount*(loop: Loop): int {.inline.}

# idle handlers
proc addIdle*(loop: Loop, cb: Callback): int {.inline.}
proc removeIdle*(loop: Loop, id: int) {.inline.}

# observers
proc observe*(loop: Loop; varPtr: ptr uint64; cb: ObserverCallback): Observer
proc cancelObserver*(obs: Observer)
```

## Related

- [types](types.md) — `EventType`, callbacks, `TimerId`
- [platform](platform.md) — the underlying multiplexer
