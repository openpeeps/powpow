## tests/bench_concurrent_events.nim — Concurrency & latency benchmarks for the
## powpow event loop (macOS kqueue / Linux epoll).
##
## Three benchmark groups:
##   1. bench_variable_cost   — mix fast + slow callbacks, latency distribution
##   2. bench_hol_blocking    — head-of-line blocking by slow callbacks
##   3. bench_capacity_sweep  — N from 100 to 50k, throughput + latency table
##
## Run:  nim c -r tests/bench_concurrent_events.nim
## Perf: nim c -d:release -r tests/bench_concurrent_events.nim

import ../src/powpow
import std/[unittest, monotimes, strformat, algorithm, tables]

when not defined(windows):
  import std/posix

  # Bump file descriptor limit so we can create thousands of pipes
  var rlim: RLimit
  if getrlimit(RLIMIT_NOFILE, rlim) == 0 and rlim.rlim_cur < rlim.rlim_max:
    rlim.rlim_cur = rlim.rlim_max
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

  proc percentiles(data: var seq[int64], count: int): tuple[min, p50, p99, max: int64] =
    ## Sort the first `count` elements and compute percentiles.
    var live = newSeq[int64](count)
    for i in 0 ..< count:
      live[i] = data[i]
    live.sort(system.cmp[int64])
    result.min = live[0]
    result.max = live[count - 1]
    result.p50 = live[count div 2]
    result.p99 = live[(count * 99) div 100]

  # ── Group 1: Variable-cost dispatch ───────────────────────────────────────

  test "bench_variable_cost":
    ## Mix fast (≈0µs) and slow (≈100µs) callbacks. Measures how variable
    ## callback cost affects per-event dispatch latency.
    const N = 4096
    const SlowRatio = 30          # 30% slow callbacks
    var fired = 0
    var latencies = newSeq[int64](N)
    var latIdx = 0
    let loop = newLoop()
    var pipes = newSeq[array[2, cint]](N)
    # Map read-fd → true if slow. Avoids closure capture of loop index.
    var slowFds = initTable[cint, bool]()

    for i in 0 ..< N:
      pipes[i] = createPipe()
      slowFds[pipes[i][0].int.cint] = (i mod 100) < SlowRatio
      loop.register(pipes[i][0].int, {Read}) do (fd: int, ev: set[EventType]):
        var b: array[16, byte]
        discard read(fd.cint, addr b[0], b.len)
        if slowFds.getOrDefault(fd.cint, false):
          # Busy-wait ~100µs to simulate work
          let spinEnd = monoUs() + 100
          while monoUs() < spinEnd:
            discard
        latencies[latIdx] = monoUs()
        inc latIdx
        inc fired
        if fired >= N: loop.stop()

    # Safety timeout
    discard loop.addTimer(5000) do (id: int):
      loop.stop()

    let t0 = monoUs()
    # Write to all pipes before running — triggers all events at once
    for i in 0 ..< N:
      var b: byte = 1
      discard write(pipes[i][1], addr b, 1)
    loop.run()
    let elapsed = monoUs() - t0

    # Compute latencies relative to first event
    let base = latencies[0]
    for i in 0 ..< latIdx:
      latencies[i] = latencies[i] - base
    let (lo, p50, p99, hi) = percentiles(latencies, latIdx)

    let fastCount = N - (N * SlowRatio div 100)
    let slowCount = N * SlowRatio div 100
    echo &"  bench_variable_cost  N={N}  fast={fastCount}  slow={slowCount}"
    echo &"    throughput:  {N*1_000_000 div max(elapsed, 1)}/s  ({elapsed}us total)"
    echo &"    latency:  min={lo}us  p50={p50}us  p99={p99}us  max={hi}us"

    for p in pipes:
      discard close(p[0]); discard close(p[1])
    check fired == N
    loop.close()

  # ── Group 2: Head-of-line blocking ───────────────────────────────────────

  test "bench_hol_blocking":
    ## Measures how much slow callbacks (200µs) delay fast callbacks in the
    ## same kevent/epoll batch. Runs twice: baseline (no slow) and with slow.
    const NFast = 1024
    const NSlow = 64

    proc runHOL(nSlow: int): tuple[p50, p99, max: int64] =
      var totalFired = 0
      let total = NFast + nSlow
      var fastLats = newSeq[int64](NFast)
      var fastIdx = 0
      let loop = newLoop()
      var pipes = newSeq[array[2, cint]](total)
      # Map read-fd → true if slow. Avoids closure capture of loop index.
      var slowFds = initTable[cint, bool]()

      for i in 0 ..< total:
        pipes[i] = createPipe()
        slowFds[pipes[i][0].int.cint] = (i >= NFast)
        loop.register(pipes[i][0].int, {Read}) do (fd: int, ev: set[EventType]):
          var b: array[16, byte]
          discard read(fd.cint, addr b[0], b.len)
          if slowFds.getOrDefault(fd.cint, false):
            # Busy-wait ~200µs
            let spinEnd = monoUs() + 200
            while monoUs() < spinEnd:
              discard
          else:
            fastLats[fastIdx] = monoUs()
            inc fastIdx
          inc totalFired
          if totalFired >= total: loop.stop()

      discard loop.addTimer(5000) do (id: int):
        loop.stop()

      for i in 0 ..< total:
        var b: byte = 1
        discard write(pipes[i][1], addr b, 1)
      loop.run()

      for p in pipes:
        discard close(p[0]); discard close(p[1])
      loop.close()

      # Make latencies relative to first fast event
      if fastIdx > 0:
        let base = fastLats[0]
        for i in 0 ..< fastIdx:
          fastLats[i] = fastLats[i] - base
      let (_, p50, p99, max) = percentiles(fastLats, fastIdx)
      result = (p50, p99, max)

    # Baseline: no slow callbacks
    let (bP50, bP99, bMax) = runHOL(0)

    # With slow callbacks
    let (hP50, hP99, hMax) = runHOL(NSlow)

    echo &"  bench_hol_blocking  fast={NFast}  slow={NSlow}"
    echo &"    baseline (0 slow):    p50={bP50}us  p99={bP99}us  max={bMax}us"
    echo &"    with {NSlow} slow (200us): p50={hP50}us  p99={hP99}us  max={hMax}us"
    echo &"    hol penalty:          p50=+{hP50 - bP50}us  p99=+{hP99 - bP99}us"

  # ── Group 3: Capacity scaling sweep ──────────────────────────────────────

  test "bench_capacity_sweep":
    ## Ramps N from 100 to 50k. Finds the throughput peak and where latency
    ## starts to degrade — the "how many concurrent events" answer.
    const Sizes = [100, 500, 1_000, 2_000, 4_000, 8_000, 12_000]

    echo "  bench_capacity_sweep"
    echo "         N      elapsed    throughput    us/ev    p50    p99    max"
    echo "    --------  ----------  ------------  ------  -----  -----  -----"

    for N in Sizes:
      var fired = 0
      var latencies = newSeq[int64](N)
      var latIdx = 0
      let loop = newLoop()
      var pipes = newSeq[array[2, cint]](N)

      for i in 0 ..< N:
        pipes[i] = createPipe()
        loop.register(pipes[i][0].int, {Read}) do (fd: int, ev: set[EventType]):
          var b: array[16, byte]
          discard read(fd.cint, addr b[0], b.len)
          latencies[latIdx] = monoUs()
          inc latIdx
          inc fired
          if fired >= N: loop.stop()

      discard loop.addTimer(5000) do (id: int):
        loop.stop()

      let t0 = monoUs()
      for i in 0 ..< N:
        var b: byte = 1
        discard write(pipes[i][1], addr b, 1)
      loop.run()
      let elapsed = monoUs() - t0

      let base = latencies[0]
      for i in 0 ..< latIdx:
        latencies[i] = latencies[i] - base
      let (lo, p50, p99, hi) = percentiles(latencies, latIdx)

      let throughput = N * 1_000_000 div max(elapsed, 1)
      let usPerEv = elapsed div max(N, 1)

      echo &"    {N:>8}  {elapsed:>9}us  {throughput:>10}/s  {usPerEv:>7}  {p50:>5}  {p99:>5}  {hi:>5}"

      for p in pipes:
        discard close(p[0]); discard close(p[1])
      check fired == N
      loop.close()
