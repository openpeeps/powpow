## tests/test_loop.nim — Smoke tests for the powpow event loop.
##
## Tests: timer, interval, deferred calls, fd eventing, stop.

import ../src/powpow
import std/[times, unittest, monotimes, os, net, posix]

proc monoMs(): int64 {.inline.} =
  getMonoTime().ticks div 1_000_000

test "test_one_shot_timer":
  var fired = false
  let loop = newLoop()
  var i = 0
  discard loop.addTimer(10) do (id: int):
    fired = true
    inc i
    loop.stop()
  loop.run()
  doAssert fired, "one-shot timer should have fired"
  assert i == 1, "one-shot timer should fire exactly once, got " & $i
  loop.close()

test "test_interval_timer":
  var count = 0
  let loop = newLoop()
  discard loop.addInterval(10) do (id: int):
    inc count
    if count >= 3:
      loop.cancelTimer(TimerId(id))
      loop.stop()
  loop.run()
  doAssert count == 3, "interval should fire exactly 3 times, got " & $count
  loop.close()

test "test_deferred_call":
  var called = false
  let loop = newLoop()
  loop.deferCall(proc() =
    called = true
    loop.stop()
  )
  loop.run()
  doAssert called, "deferred callback should have fired"
  loop.close()

test "test_timer_ordering":
  var order: seq[int] = @[]
  let loop = newLoop()
  discard loop.addTimer(50) do (id: int):
    order.add(2)
    loop.stop()
  discard loop.addTimer(10) do (id: int):
    order.add(1)
  loop.run()
  doAssert order == @[1, 2], "timers should fire in deadline order, got " & $order
  loop.close()

# ── Test 5: fd eventing via pipe ─────────────────────────────────────────────

test "test_fd_eventing":
  # Create a pipe; write to one end, poll the other.
  var fds: array[2, cint]
  let ret = pipe(fds)
  doAssert ret == 0, "pipe() failed"

  var gotRead = false
  let loop = newLoop()

  loop.register(fds[0].int, {Read}) do (fd: int, ev: set[EventType]):
    gotRead = true
    # drain the pipe
    var buf: array[64, char]
    discard read(fd.cint, addr buf[0], buf.len)
    loop.unregister(fd)
    loop.stop()

  # Write a byte after a short delay to give the loop time to poll.
  discard loop.addTimer(5) do (id: int):
    var msg = "hello"
    discard write(fds[1], addr msg[0], msg.len)

  loop.run()
  doAssert gotRead, "fd read event should have fired"

  discard close(fds[0])
  discard close(fds[1])
  loop.close()

test "test_is_running":
  let loop = newLoop()
  doAssert not loop.isRunning(), "loop should not be running before run()"
  discard loop.addTimer(5) do (id: int):
    loop.stop()
  loop.run()
  doAssert not loop.isRunning(), "loop should not be running after stop()"
  loop.close()

test "test_cancel_timer":
  var fired = false
  let loop = newLoop()
  let id = loop.addTimer(10) do (tId: int):
    fired = true
  loop.cancelTimer(id)
  discard loop.addTimer(30) do (tId: int):
    loop.stop()
  loop.run()
  doAssert not fired, "cancelled timer should not fire"
  loop.close()

