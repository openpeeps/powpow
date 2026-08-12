## tests/test_loop.nim — Smoke tests for the powpow event loop.
##
## Tests: timer, interval, deferred calls, fd eventing, stop.

import ../src/powpow
import std/[times, unittest, monotimes, os, net]

when defined(linux) or defined(macosx) or defined(bsd):
  # fd eventing is exercised with a pipe. The Windows iocp backend can only
  # register IOCP-compatible handles (sockets), so this is POSIX-only.
  import std/posix
  proc c_pipe(fds: var array[2, cint]): cint = posix.pipe(fds)
  proc c_read(fd: cint, buf: pointer, count: cint): cint =
    posix.read(fd, buf, count).cint
  proc c_write(fd: cint, buf: pointer, count: cint): cint =
    posix.write(fd, buf, count).cint
  proc c_close(fd: cint): cint = posix.close(fd).cint

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

when defined(linux) or defined(macosx) or defined(bsd):
  test "test_fd_eventing":
    # Create a pipe; write to one end, poll the other.
    var fds: array[2, cint]
    let ret = c_pipe(fds)
    doAssert ret == 0, "pipe() failed"

    var gotRead = false
    let loop = newLoop()

    loop.register(fds[0].int, {Read}) do (fd: int, ev: set[EventType]):
      gotRead = true
      # drain the pipe
      var buf: array[64, char]
      discard c_read(fd.cint, addr buf[0], buf.len.cint)
      loop.unregister(fd)
      loop.stop()

    # Write a byte after a short delay to give the loop time to poll.
    discard loop.addTimer(5) do (id: int):
      var msg = "hello"
      discard c_write(fds[1], addr msg[0], msg.len.cint)

    loop.run()
    doAssert gotRead, "fd read event should have fired"

    discard c_close(fds[0])
    discard c_close(fds[1])
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

# ── Test 8: timer pause/resume ───────────────────────────────────────────────

test "test_pause_one_shot":
  var fired = false
  let loop = newLoop()
  let timerId = loop.addTimer(50) do (id: int):
    fired = true
  loop.pauseTimer(timerId)
  discard loop.addTimer(100) do (id: int):
    loop.stop()
  loop.run()
  doAssert not fired, "paused one-shot timer should not fire"
  loop.close()

test "test_pause_resume_one_shot":
  var firedAt = 0
  let loop = newLoop()
  let t0 = monoMs()
  let timerId = loop.addTimer(200) do (id: int):
    firedAt = (monoMs() - t0).int
    loop.stop()
  loop.pauseTimer(timerId)
  discard loop.addTimer(50) do (id: int):
    loop.resumeTimer(timerId)
  loop.run()
  doAssert firedAt >= 150, "resumed timer should fire ~200ms from resume, got " & $firedAt
  loop.close()

test "test_pause_interval":
  var count = 0
  let loop = newLoop()
  let intId = loop.addInterval(30) do (id: int):
    inc count
  discard loop.addTimer(80) do (id: int):
    loop.pauseTimer(intId)
  discard loop.addTimer(200) do (id: int):
    loop.stop()
  loop.run()
  doAssert count <= 4, "paused interval should fire at most 4 times (80ms/30ms+1), got " & $count
  loop.close()

test "test_pause_nonexistent":
  let loop = newLoop()
  loop.pauseTimer(TimerId(99999))
  loop.resumeTimer(TimerId(99999))
  discard loop.addTimer(10) do (id: int):
    loop.stop()
  loop.run()
  loop.close()

test "test_pause_cancel_interaction":
  var fired = false
  let loop = newLoop()
  let timerId = loop.addTimer(50) do (id: int):
    fired = true
  loop.pauseTimer(timerId)
  loop.cancelTimer(timerId)
  discard loop.addTimer(100) do (id: int):
    loop.stop()
  loop.run()
  doAssert not fired, "cancelled+paused timer should not fire"
  loop.close()

# ── Test 14: timer counter drift regression ──────────────────────────────────

test "test_timer_count_returns_to_zero":
  # Long one-shot timers cascade across wheel levels (addToWheel re-adds a
  # counted node) and intervals re-arm through addToWheel on every fire. Both
  # paths used to `inc totalTimers` again, inflating the counter and keeping
  # the cancelled-set prune from ever running. Assert the counter returns to 0.
  let loop = newLoop()
  var fired = 0
  for d in [300, 350, 450, 650, 900]:
    discard loop.addTimer(d) do (id: int):
      inc fired
  var intervalTicks = 0
  var intervalId: TimerId
  intervalId = loop.addInterval(5) do (id: int):
    inc intervalTicks
    if intervalTicks >= 3:
      loop.cancelTimer(intervalId)
  var polls = 0
  while loop.timerCount > 0 and polls < 50_000:
    loop.poll(1)
    inc polls
  doAssert polls < 50_000, "timers did not resolve; timerCount=" & $loop.timerCount
  doAssert fired == 5, "all one-shot timers should fire, got " & $fired
  doAssert intervalTicks >= 3, "interval should have ticked, got " & $intervalTicks
  doAssert loop.timerCount == 0, "totalTimers drifted to " & $loop.timerCount
  loop.close()

# ── Test 13: observer ────────────────────────────────────────────────────────

test "test_observer_value_change":
  var observed: uint64 = 0
  var cbVal: uint64 = 0
  let loop = newLoop()
  let obs = loop.observe(addr observed) do (val: uint64):
    cbVal = val
  discard loop.addTimer(10) do (id: int):
    observed = 42
  discard loop.addTimer(30) do (id: int):
    loop.stop()
  loop.run()
  doAssert cbVal == 42, "observer callback should fire with new value, got " & $cbVal
  loop.close()

test "test_observer_no_change":
  var cbCount = 0
  let loop = newLoop()
  var x: uint64 = 0
  discard loop.observe(addr x) do (val: uint64):
    inc cbCount
  discard loop.addTimer(30) do (id: int):
    loop.stop()
  loop.run()
  doAssert cbCount == 0, "observer should not fire when value unchanged, got " & $cbCount
  loop.close()

test "test_observer_cancel":
  var cbCount = 0
  let loop = newLoop()
  var x: uint64 = 0
  let obs = loop.observe(addr x) do (val: uint64):
    inc cbCount
  discard loop.addTimer(10) do (id: int):
    cancelObserver(obs)
    x = 42
  discard loop.addTimer(30) do (id: int):
    loop.stop()
  loop.run()
  doAssert cbCount == 0, "cancelled observer should not fire, got " & $cbCount
  loop.close()

test "test_close_buffer_release_after_close_no_leak":
  # A connection that returns its readBuf AFTER loop.close() must not be
  # re-pooled into the already-freed pool (shared-memory leak per connection).
  let loop = newLoop()
  doAssert not loop.closed
  var buf = acquireBuf(loop)
  loop.close()
  doAssert loop.closed, "close() must set the closed flag"
  doAssert loop.bufPool.len == 0, "pool must be drained after close"
  releaseBuf(loop, buf)   # would leak if re-pooled
  doAssert loop.bufPool.len == 0,
    "released-after-close buffer must be deallocated, not pooled"

test "test_close_idempotent":
  let loop = newLoop()
  loop.close()
  loop.close()   # must not crash / double-free
  doAssert loop.closed


