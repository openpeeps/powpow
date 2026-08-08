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
