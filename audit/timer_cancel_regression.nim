## audit/07_timer_cancel_regression.nim
##
## Regression guard for the timer wheel: a cancelled timer must NEVER fire its
## callback, even with a large number of cancelled-but-unfired timers in the
## wheel (the previous concern about the `cancelled` set being cleared early is
## a confirmed false positive, but this keeps it pinned).

import powpow
import std/[unittest]

suite "cancelled timers never fire":

  test "bulk-cancelled long timers never fire":
    let loop = newLoop()
    var fired = 0
    for i in 0 ..< 500:
      let id = loop.addTimer(1000) do (tid: int):
        inc fired
      loop.cancelTimer(id)
    discard loop.addTimer(1500) do (tid: int):
      loop.stop()
    loop.run()
    check fired == 0
    loop.close()

  test "cancelled + paused timer never fires":
    let loop = newLoop()
    var fired = false
    let id = loop.addTimer(50) do (tid: int):
      fired = true
    loop.pauseTimer(id)
    loop.cancelTimer(id)
    discard loop.addTimer(100) do (tid: int):
      loop.stop()
    loop.run()
    check not fired
    loop.close()
