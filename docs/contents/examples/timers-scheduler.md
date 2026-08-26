---
title: Timer wheel
description: "One-shot timers, intervals, deferred calls and idle handlers."
keywords: ["powpow", "example", "timers_scheduler"]
---

# Timer wheel

Tour of the loop's scheduling facilities: deferred callbacks run before the next poll iteration, idle handlers fire whenever the loop has nothing else queued, one-shot timers and repeating intervals come off a hierarchical timing wheel. Runs about 8 seconds and stops itself.

Source: [`examples/timers_scheduler.nim`](../../examples/timers_scheduler.nim)

```nim
## examples/timers_scheduler.nim — Timer wheel demo.
##
## Demonstrates the event loop's timer facilities: one-shot timers, repeating
## intervals, deferred callbacks (run before the next poll), and idle handlers
## (run when the loop has nothing else to do). Runs for ~8 seconds, then stops.
##
## Run:
##   nim c -r examples/timers_scheduler.nim

import ../src/powpow
import std/[times, strutils]

let loop = newLoop()
let t0 = epochTime()

proc ts(): string =
  ((epochTime() - t0) * 1000).formatFloat(ffDecimal, 0) & "ms"

# Deferred callback — runs before the very first poll iteration.
loop.deferCall proc() =
  echo ts(), "  [deferred] runs before the first I/O poll"

# Idle handler — runs whenever the loop is otherwise idle.
discard loop.addIdle proc() =
  echo ts(), "  [idle] loop has nothing to do"

# One-shot timer — fires once after 1s.
discard loop.addTimer(1000) do (id: int):
  echo ts(), "  [one-shot] fired (timer #", id, ")"

# Repeating interval — fires every 500ms.
discard loop.addInterval(500) do (id: int):
  echo ts(), "  [interval] tick (timer #", id, ")"

# A one-shot that cancels the interval after 4 seconds.
var intervalId: TimerId
intervalId = loop.addInterval(250) do (id: int):
  echo ts(), "  [interval#", id, "] fast tick"
discard loop.addTimer(4000) do (id: int):
  echo ts(), "  [one-shot] cancelling interval #", int(intervalId)
  loop.cancelTimer(intervalId)

# Stop the loop after ~8 seconds.
discard loop.addTimer(8000) do (id: int):
  echo ts(), "  stopping"
  loop.stop()

echo "⚡ timer scheduler running for ~8s — watch the ticks"
loop.run()
```

## Running

```bash
nim c -r examples/timers_scheduler.nim
```

## How it works

- `loop.deferCall(proc)` executes before the first I/O poll of the next iteration.
- `loop.addIdle(cb)` returns a handle; the callback runs whenever the wheel and poll have no work, throttled internally.
- `addTimer(ms, cb)` fires once; `addInterval(ms, cb)` repeats; both return a `TimerId` usable with `cancelTimer`, `pauseTimer`, `resumeTimer`.
- Timestamps in the log make firing order visible: deferred first, then timers aligned to wheel slots.

[Event loop guide](../core/event-loop.md) and [Loop API](../api/loop.md).

