## tests/test_bench_event_loop.nim — Benchmark and stress tests for the powpow event loop.
##
## Measures timer wheel throughput, fd event latency, mixed load,
## and stress tests pointer dispatch / zombie sweep / batch limits.
##
## Run:  nim c -r tests/test_bench_event_loop.nim
## Perf: nim c -d:release -r tests/test_bench_event_loop.nim

import ../src/powpow
import std/[times, unittest, monotimes, os, posix, strformat]

# Bump file descriptor limit so we can create thousands of pipes
var rlim: RLimit
if getrlimit(RLIMIT_NOFILE, rlim) == 0 and rlim.rlim_cur < 16384:
  rlim.rlim_cur = min(rlim.rlim_max, 16384)
  discard setrlimit(RLIMIT_NOFILE, rlim)

proc monoUs(): int64 {.inline.} =
  getMonoTime().ticks div 1_000

proc createPipe(): array[2, cint] =
  var fds: array[2, cint]
  if pipe(fds) < 0:
    raise newException(OSError, "pipe() failed")
  for i in 0 .. 1:
    let flags = fcntl(fds[i], F_GETFL, 0)
    if flags >= 0:
      discard fcntl(fds[i], F_SETFL, flags or O_NONBLOCK)
  fds

suite "bench_event_loop":

  # ══════════════════════════════════════════════════════════════════════════
  # Timer wheel
  # ══════════════════════════════════════════════════════════════════════════

  test "timer_10k_one_shot":
    const N = 10_000
    var fired = 0
    let loop = newLoop()
    let t0 = monoUs()
    for i in 0 ..< N:
      discard loop.addTimer(1 + (i mod 10)) do (id: int):
        inc fired
    discard loop.addTimer(100) do (id: int):
      loop.stop()
    loop.run()
    let elapsed = monoUs() - t0
    echo &"  timer_10k_one_shot  N={N}  fired={fired}  {elapsed}us  {N*1_000_000 div max(elapsed, 1)}/s"
    check fired == N
    loop.close()

  test "timer_10k_cancel":
    const N = 10_000
    var fired = 0
    let loop = newLoop()
    var ids: seq[TimerId]
    for i in 0 ..< N:
      ids.add(loop.addTimer(1 + (i mod 10)) do (id: int):
        inc fired)
    for i in 0 ..< N div 2:
      loop.cancelTimer(ids[i])
    discard loop.addTimer(200) do (id: int):
      loop.stop()
    loop.run()
    echo &"  timer_10k_cancel  N={N}  half cancelled  fired={fired}"
    check fired == N - (N div 2)
    loop.close()

  test "timer_ordering_1k":
    # Each timer gets a unique delay so no two share a Level-0 slot
    const N = 1000
    var order: seq[int]
    let loop = newLoop()
    for i in 0 ..< N:
      discard loop.addTimer(10 + i * 2) do (id: int):
        order.add(id)
    discard loop.addTimer(3000) do (id: int):
      loop.stop()
    loop.run()
    check order.len == N
    var inOrder = true
    for i in 1 ..< order.len:
      if order[i - 1] > order[i]:
        inOrder = false
        break
    check inOrder
    echo &"  timer_ordering_1k  N={N}  in-order={inOrder}"
    loop.close()

  test "timer_interval_1k":
    # Each interval fires 3 times then cancels itself.
    # Uses a helper proc so each closure captures a unique `idx` value.
    const N = 1000
    const Fires = 3
    var count = 0
    let loop = newLoop()
    var fireCounts = newSeq[int](N)
    proc addOne(loop: Loop; idx: int) =
      discard loop.addInterval(2) do (id: int):
        inc count
        inc fireCounts[idx]
        if fireCounts[idx] >= Fires:
          loop.cancelTimer(TimerId(id))
    for i in 0 ..< N:
      addOne(loop, i)
    discard loop.addTimer(500) do (id: int):
      loop.stop()
    loop.run()
    let expected = N * Fires
    echo &"  timer_interval_1k  N={N}x{Fires}  fired={count}  expected={expected}"
    check count == expected
    loop.close()

  test "timer_mass_insert":
    const N = 100_000
    let loop = newLoop()
    let t0 = monoUs()
    for i in 0 ..< N:
      discard loop.addTimer(1 + (i mod 100)) do (id: int):
        discard
    let elapsed = monoUs() - t0
    echo &"  timer_mass_insert  N={N}  {elapsed}us  {N*1_000_000 div max(elapsed, 1)}/s"
    discard loop.addTimer(200) do (id: int):
      loop.stop()
    loop.run()
    loop.close()

  test "timer_far_future":
    let loop = newLoop()
    var nearFired = false
    var farFired = false
    discard loop.addTimer(50) do (id: int):
      nearFired = true
      loop.stop()
    discard loop.addTimer(30_000) do (id: int):
      farFired = true
    loop.run()
    check nearFired
    check not farFired
    echo &"  timer_far_future  near={nearFired}  far={farFired}  (far timer >1min should not fire)"
    loop.close()

  test "timer_batch_cap":
    const N = 10_000
    var fired = 0
    let loop = newLoop()
    for i in 0 ..< N:
      discard loop.addTimer(0) do (id: int):
        inc fired
    discard loop.addTimer(500) do (id: int):
      loop.stop()
    loop.run()
    echo &"  timer_batch_cap  N={N}  fired={fired}"
    check fired == N
    loop.close()

  # ══════════════════════════════════════════════════════════════════════════
  # fd eventing
  # ══════════════════════════════════════════════════════════════════════════

  test "fd_1k_pipes":
    const N = 1000
    var pipes = newSeq[array[2, cint]](N)
    var fired = 0
    let loop = newLoop()
    for i in 0 ..< N:
      pipes[i] = createPipe()
    let t0 = monoUs()
    for i in 0 ..< N:
      loop.register(pipes[i][0].int, {Read}) do (fd: int, ev: set[EventType]):
        var buf: array[64, byte]
        discard read(fd.cint, addr buf[0], 64)
        inc fired
        loop.unregister(fd)
    for i in 0 ..< N:
      var b = "x"
      discard write(pipes[i][1], addr b[0], 1)
    discard loop.addTimer(1000) do (id: int):
      loop.stop()
    loop.run()
    let elapsed = monoUs() - t0
    echo &"  fd_1k_pipes  N={N}  fired={fired}  {elapsed}us  {N*1_000_000 div max(elapsed, 1)}/s"
    check fired == N
    for p in pipes:
      discard close(p[0]); discard close(p[1])
    loop.close()

  test "fd_register_churn":
    const N = 5000
    const Rounds = 5
    var pipes = newSeq[array[2, cint]](N)
    for i in 0 ..< N:
      pipes[i] = createPipe()
    let loop = newLoop()
    let t0 = monoUs()
    for round in 0 ..< Rounds:
      var fired = 0
      for i in 0 ..< N:
        loop.register(pipes[i][0].int, {Read}) do (fd: int, ev: set[EventType]):
          var buf: array[64, byte]
          discard read(fd.cint, addr buf[0], 64)
          inc fired
      for i in 0 ..< N:
        var b = "x"
        discard write(pipes[i][1], addr b[0], 1)
      discard loop.addTimer(50) do (id: int):
        loop.stop()
      loop.run()
      check fired == N
      # Unregister all without closing
      for i in 0 ..< N:
        loop.unregister(pipes[i][0].int)
    let elapsed = monoUs() - t0
    echo &"  fd_register_churn  N={N}  rounds={Rounds}  {elapsed}us  avg={(elapsed div Rounds)}us/round"
    for p in pipes:
      discard close(p[0]); discard close(p[1])
    loop.close()

  test "fd_stale_event_safety":
    const N = 500
    var pipes = newSeq[array[2, cint]](N)
    for i in 0 ..< N:
      pipes[i] = createPipe()
    let loop = newLoop()
    # Register, write, unregister, re-register new callback
    for i in 0 ..< N:
      loop.register(pipes[i][0].int, {Read}) do (fd: int, ev: set[EventType]):
        var buf: array[64, byte]
        discard read(fd.cint, addr buf[0], 64)
        loop.unregister(fd)
    for i in 0 ..< N:
      var b = "x"
      discard write(pipes[i][1], addr b[0], 1)
    # Wait a tiny bit for events to be queued
    discard loop.addTimer(5) do (id: int):
      # Re-register with a NEW callback (should replace old watcher)
      for i in 0 ..< N:
        loop.register(pipes[i][0].int, {Read}) do (fd2: int, ev2: set[EventType]):
          var buf: array[64, byte]
          discard read(fd2.cint, addr buf[0], 64)
          # This should fire for each pipe — old stale events skipped
          loop.unregister(fd2)
      loop.stop()
    loop.run()
    # Drain remaining events
    var finalCount = 0
    loop.register(pipes[0][0].int, {Read}) do (fd: int, ev: set[EventType]):
      var buf: array[64, byte]
      discard read(fd.cint, addr buf[0], 64)
      inc finalCount
    discard loop.addTimer(20) do (id: int):
      loop.stop()
    loop.run()
    echo &"  fd_stale_event_safety  N={N}  finalCount={finalCount}  (0 = no stale events leaked through)"
    check finalCount == 0
    for p in pipes:
      discard close(p[0]); discard close(p[1])
    loop.close()

  test "fd_modify_stress":
    const N = 200
    var pipes = newSeq[array[2, cint]](N)
    for i in 0 ..< N:
      pipes[i] = createPipe()
    let loop = newLoop()
    var readFired = 0
    var writeFired = 0
    for i in 0 ..< N:
      loop.register(pipes[i][0].int, {Read, Write}) do (fd: int, ev: set[EventType]):
        if Read in ev or Hup in ev:
          inc readFired
          var buf: array[64, byte]
          discard read(fd.cint, addr buf[0], 64)
        if Write in ev:
          inc writeFired
    # Write data, then modify to Read-only
    for i in 0 ..< N:
      var b = "x"
      discard write(pipes[i][1], addr b[0], 1)
    discard loop.addTimer(10) do (id: int):
      for i in 0 ..< N:
        loop.modify(pipes[i][0].int, {Read})
    discard loop.addTimer(50) do (id: int):
      loop.stop()
    loop.run()
    echo &"  fd_modify_stress  N={N}  readFired={readFired}  writeFired={writeFired}"
    check readFired == N
    for p in pipes:
      discard close(p[0]); discard close(p[1])
    loop.close()

  # ══════════════════════════════════════════════════════════════════════════
  # Mixed load
  # ══════════════════════════════════════════════════════════════════════════

  test "mixed_timers_fd":
    const TimerN = 2000
    const PipeN = 100
    var pipes = newSeq[array[2, cint]](PipeN)
    for i in 0 ..< PipeN:
      pipes[i] = createPipe()
    var timerFired = 0
    var fdFired = 0
    let loop = newLoop()
    for i in 0 ..< PipeN:
      loop.register(pipes[i][0].int, {Read}) do (fd: int, ev: set[EventType]):
        var buf: array[64, byte]
        discard read(fd.cint, addr buf[0], 64)
        inc fdFired
        loop.unregister(fd)
    for i in 0 ..< TimerN:
      discard loop.addTimer(1 + (i mod 20)) do (id: int):
        inc timerFired
    for i in 0 ..< PipeN:
      var b = "x"
      discard write(pipes[i][1], addr b[0], 1)
    discard loop.addTimer(200) do (id: int):
      loop.stop()
    loop.run()
    echo &"  mixed_timers_fd  timers={timerFired}/{TimerN}  fd={fdFired}/{PipeN}"
    check timerFired == TimerN
    check fdFired == PipeN
    for p in pipes:
      discard close(p[0]); discard close(p[1])
    loop.close()

  test "mixed_deferred_fd":
    const DeferN = 2000
    const PipeN = 100
    var pipes = newSeq[array[2, cint]](PipeN)
    for i in 0 ..< PipeN:
      pipes[i] = createPipe()
    var deferFired = 0
    var fdFired = 0
    let loop = newLoop()
    for i in 0 ..< PipeN:
      loop.register(pipes[i][0].int, {Read}) do (fd: int, ev: set[EventType]):
        var buf: array[64, byte]
        discard read(fd.cint, addr buf[0], 64)
        inc fdFired
    for i in 0 ..< DeferN:
      loop.deferCall(proc() =
        inc deferFired)
    for i in 0 ..< PipeN:
      var b = "x"
      discard write(pipes[i][1], addr b[0], 1)
    discard loop.addTimer(200) do (id: int):
      loop.stop()
    loop.run()
    echo &"  mixed_deferred_fd  deferred={deferFired}/{DeferN}  fd={fdFired}/{PipeN}"
    check deferFired == DeferN
    for p in pipes:
      discard close(p[0]); discard close(p[1])
    loop.close()

  test "mixed_idle_does_not_starve":
    const PipeN = 50
    var pipes = newSeq[array[2, cint]](PipeN)
    for i in 0 ..< PipeN:
      pipes[i] = createPipe()
    var fdFired = 0
    var idleFired = 0
    let loop = newLoop()
    for i in 0 ..< PipeN:
      loop.register(pipes[i][0].int, {Read}) do (fd: int, ev: set[EventType]):
        var buf: array[64, byte]
        discard read(fd.cint, addr buf[0], 64)
        inc fdFired
        loop.unregister(fd)
    discard loop.addIdle(proc() =
      inc idleFired)
    for i in 0 ..< PipeN:
      var b = "x"
      discard write(pipes[i][1], addr b[0], 1)
    discard loop.addTimer(200) do (id: int):
      loop.stop()
    loop.run()
    echo &"  mixed_idle_does_not_starve  fd={fdFired}/{PipeN}  idle={idleFired}"
    check fdFired == PipeN
    # Idle may fire briefly after fd events drain; just check it doesn't block fds
    for p in pipes:
      discard close(p[0]); discard close(p[1])
    loop.close()

  test "mixed_all_load":
    const
      TimerN = 500
      PipeN = 50
      DeferN = 500
    var pipes = newSeq[array[2, cint]](PipeN)
    for i in 0 ..< PipeN:
      pipes[i] = createPipe()
    var timerFired = 0
    var fdFired = 0
    var deferFired = 0
    let loop = newLoop()
    for i in 0 ..< PipeN:
      loop.register(pipes[i][0].int, {Read}) do (fd: int, ev: set[EventType]):
        var buf: array[64, byte]
        discard read(fd.cint, addr buf[0], 64)
        inc fdFired
        loop.unregister(fd)
    for i in 0 ..< TimerN:
      discard loop.addTimer(1 + (i mod 30)) do (id: int):
        inc timerFired
    for i in 0 ..< DeferN:
      loop.deferCall(proc() =
        inc deferFired)
    for i in 0 ..< PipeN:
      var b = "x"
      discard write(pipes[i][1], addr b[0], 1)
    discard loop.addTimer(500) do (id: int):
      loop.stop()
    loop.run()
    echo &"  mixed_all_load  timers={timerFired}/{TimerN}  fd={fdFired}/{PipeN}  deferred={deferFired}/{DeferN}"
    check timerFired == TimerN
    check fdFired == PipeN
    check deferFired == DeferN
    for p in pipes:
      discard close(p[0]); discard close(p[1])
    loop.close()

  # ══════════════════════════════════════════════════════════════════════════
  # Stress / edge cases
  # ══════════════════════════════════════════════════════════════════════════

  test "stress_cancel_during_fire":
    let loop = newLoop()
    var cancelTarget: TimerId
    var targetFired = false
    discard loop.addTimer(5) do (id: int):
      loop.cancelTimer(cancelTarget)
    cancelTarget = loop.addTimer(10) do (id: int):
      targetFired = true
    discard loop.addTimer(50) do (id: int):
      loop.stop()
    loop.run()
    check not targetFired
    echo &"  stress_cancel_during_fire  targetFired={targetFired}  (should be false)"
    loop.close()

  test "stress_interval_cancel_self":
    var count = 0
    let loop = newLoop()
    discard loop.addInterval(5) do (id: int):
      inc count
      loop.cancelTimer(TimerId(id))
      if count >= 3:
        loop.stop()
    discard loop.addTimer(100) do (id: int):
      loop.stop()
    loop.run()
    echo &"  stress_interval_cancel_self  count={count}  (should be 1, not 3)"
    check count == 1
    loop.close()

  test "stress_sweep_many_dead":
    const N = 2000
    const Rounds = 10
    var pipes = newSeq[array[2, cint]](N)
    for i in 0 ..< N:
      pipes[i] = createPipe()
    let loop = newLoop()
    for round in 0 ..< Rounds:
      for i in 0 ..< N:
        loop.register(pipes[i][0].int, {Read}) do (fd: int, ev: set[EventType]):
          var buf: array[64, byte]
          discard read(fd.cint, addr buf[0], 64)
          loop.unregister(fd)
      for i in 0 ..< N:
        var b = "x"
        discard write(pipes[i][1], addr b[0], 1)
      discard loop.addTimer(30) do (id: int):
        loop.stop()
      loop.run()
    echo &"  stress_sweep_many_dead  N={N}  rounds={Rounds}  completed"
    for p in pipes:
      discard close(p[0]); discard close(p[1])
    loop.close()

  test "stress_close_without_unregister":
    const N = 500
    var pipes = newSeq[array[2, cint]](N)
    for i in 0 ..< N:
      pipes[i] = createPipe()
    let loop = newLoop()
    for i in 0 ..< N:
      loop.register(pipes[i][0].int, {Read}) do (fd: int, ev: set[EventType]):
        discard
    loop.close()
    # Close all pipe fds manually (loop.close() only closes registered fds)
    for p in pipes:
      discard close(p[0]); discard close(p[1])
    echo &"  stress_close_without_unregister  N={N}  closed without crash"

  test "stress_register_fd_then_stop":
    var fds = createPipe()
    let loop = newLoop()
    loop.register(fds[0].int, {Read}) do (fd: int, ev: set[EventType]):
      var buf: array[64, byte]
      discard read(fd.cint, addr buf[0], 64)
      loop.stop()
    var b = "x"
    discard write(fds[1], addr b[0], 1)
    loop.run()
    discard close(fds[0]); discard close(fds[1])
    loop.close()
    echo "  stress_register_fd_then_stop  OK"

  test "stress_deferred_stop":
    let loop = newLoop()
    loop.deferCall(proc() =
      loop.stop())
    loop.run()
    loop.close()
    echo "  stress_deferred_stop  OK"

  test "stress_cancel_nonexistent":
    let loop = newLoop()
    # Cancel a timer that doesn't exist — should be a no-op
    loop.cancelTimer(TimerId(99999))
    discard loop.addTimer(10) do (id: int):
      loop.stop()
    loop.run()
    loop.close()
    echo "  stress_cancel_nonexistent  OK (no crash)"

  test "stress_remove_nonexistent_fd":
    let loop = newLoop()
    # Unregister an fd that was never registered — should be a no-op
    loop.unregister(99999)
    loop.close()
    echo "  stress_remove_nonexistent_fd  OK (no crash)"
