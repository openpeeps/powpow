## tests/test_stream.nim — Tests, benchmarks and stress tests for powpow raw-fd streaming (IoStream).
##
## Functional tests: socketpair round-trip, large write backpressure, peer-close,
## read pause/resume, closeAfterWrite EOF, writes to a closed peer.
## Benchmarks: throughput (MB/s), ping-pong message rate, many concurrent
## streams, small-write stress, pause/resume churn.
##
## Run:  nim c -r tests/test_stream.nim
## Perf: nim c -d:release -r tests/test_stream.nim

import ../src/powpow
import std/[unittest, strutils, times, monotimes, os, strformat]

when not defined(windows):
  test "test_stream_roundtrip":
    var bReceived: seq[byte] = @[]
    let loop = newLoop()
    var a, b: IoStream
    (a, b) = newStreamPair(loop,
      onData = proc(s: IoStream, data: openArray[byte]) =
        bReceived.add(data),
    )

    discard loop.addTimer(10) do (id: int):
      let n = a.write("hello powpow")
      doAssert n == 12, "write returned " & $n

    discard loop.addTimer(100) do (id: int):
      doAssert cast[string](bReceived) == "hello powpow",
        "mismatch: " & cast[string](bReceived)
      a.close()
      b.close()
      loop.stop()

    discard loop.addTimer(2000) do (id: int):
      loop.stop()

    loop.run()
    loop.close()

  test "test_stream_large_write":
    let payload = "abcdefghijklmnopqrstuvwxyz0123456789".repeat(32768)  # 1 MiB
    var received: seq[byte] = @[]
    let loop = newLoop()
    var a, b: IoStream
    (a, b) = newStreamPair(loop,
      onData = proc(s: IoStream, data: openArray[byte]) =
        received.add(data)
        if received.len == payload.len:
          doAssert cast[string](received) == payload, "large write corrupted"
          a.close()
          b.close()
          loop.stop()
    )

    discard loop.addTimer(10) do (id: int):
      let n = b.write(payload)
      doAssert n == payload.len, "write accepted " & $n & "/" & $payload.len

    discard loop.addTimer(5000) do (id: int):
      doAssert false, "large write did not complete: " & $received.len & " bytes"
      loop.stop()

    loop.run()
    loop.close()

  test "test_stream_peer_close":
    var aClosed = false
    let loop = newLoop()
    var a, b: IoStream
    (a, b) = newStreamPair(loop,
      onData = proc(s: IoStream, data: openArray[byte]) = discard,
      onClose = proc(s: IoStream) =
        if s == a:
          aClosed = true
          loop.stop()
    )

    discard loop.addTimer(10) do (id: int):
      b.close()

    discard loop.addTimer(2000) do (id: int):
      loop.stop()

    loop.run()
    doAssert aClosed, "onClose should fire when the peer closes"
    loop.close()

  test "test_stream_pause_resume":
    var received: seq[byte] = @[]
    let loop = newLoop()
    var a, b: IoStream
    (a, b) = newStreamPair(loop,
      onData = proc(s: IoStream, data: openArray[byte]) =
        received.add(data),
    )

    discard loop.addTimer(10) do (id: int):
      a.pause()
      doAssert b.write("paused data") == 11

    discard loop.addTimer(50) do (id: int):
      doAssert received.len == 0, "onData fired while paused"
      a.resume()

    discard loop.addTimer(100) do (id: int):
      doAssert cast[string](received) == "paused data",
        "after resume: " & cast[string](received)
      a.close()
      b.close()
      loop.stop()

    discard loop.addTimer(2000) do (id: int):
      loop.stop()

    loop.run()
    loop.close()

  test "test_stream_close_after_write":
    var bReceived: seq[byte] = @[]
    var bClosed = false
    let loop = newLoop()
    var a, b: IoStream
    (a, b) = newStreamPair(loop,
      onData = proc(s: IoStream, data: openArray[byte]) =
        bReceived.add(data),
      onClose = proc(s: IoStream) =
        if s == b:
          bClosed = true
    )

    discard loop.addTimer(10) do (id: int):
      doAssert a.write("eof") == 3
      a.closeAfterWrite()

    discard loop.addTimer(100) do (id: int):
      doAssert cast[string](bReceived) == "eof", "lost data: " & cast[string](bReceived)
      doAssert bClosed, "peer should observe EOF after closeAfterWrite"
      b.close()
      loop.stop()

    discard loop.addTimer(2000) do (id: int):
      loop.stop()

    loop.run()
    loop.close()

  test "test_stream_write_closed_peer":
    var aClosed = false
    let loop = newLoop()
    var a, b: IoStream
    (a, b) = newStreamPair(loop,
      onData = proc(s: IoStream, data: openArray[byte]) = discard,
      onClose = proc(s: IoStream) =
        if s == a:
          aClosed = true
    )

    discard loop.addTimer(10) do (id: int):
      b.close()
      let n = a.write("late")
      doAssert n == -1, "write to closed peer should fail, got " & $n

    discard loop.addTimer(50) do (id: int):
      doAssert aClosed, "onClose should fire after a hard write error"
      a.close()
      loop.stop()

    discard loop.addTimer(2000) do (id: int):
      loop.stop()

    loop.run()
    loop.close()

# ── Benchmarks & stress ──────────────────────────────────────────────────────

when not defined(windows):
  import std/posix

  proc monoUs(): int64 {.inline.} =
    getMonoTime().ticks div 1_000

  var rlim: RLimit
  if getrlimit(RLIMIT_NOFILE, rlim) == 0 and rlim.rlim_cur < 16384:
    rlim.rlim_cur = min(rlim.rlim_max, 16384)
    discard setrlimit(RLIMIT_NOFILE, rlim)

  test "bench_stream_throughput":
    ## Push 16 MiB through one stream pair, measure effective MB/s.
    const PayloadMb = 16
    let payload = "0123456789abcdef".repeat(PayloadMb * 64 * 1024)
    var received: int64 = 0
    var t0: int64 = 0
    let loop = newLoop()
    var a, b: IoStream
    var done = false
    (a, b) = newStreamPair(loop,
      onData = proc(s: IoStream, data: openArray[byte]) =
        received += data.len
        if received >= payload.len and not done:
          done = true
          let elapsedUs = monoUs() - t0
          echo &"  bench_stream_throughput  {PayloadMb} MiB in {elapsedUs div 1000}ms  " &
               &"{payload.len div max(elapsedUs, 1)} MB/s"
          a.close()
          b.close()
          loop.stop()
    )

    discard loop.addTimer(10) do (id: int):
      t0 = monoUs()
      let n = b.write(payload)
      doAssert n == payload.len, "write accepted " & $n & "/" & $payload.len

    discard loop.addTimer(10_000) do (id: int):
      doAssert false, "throughput did not complete: " & $received & " bytes"
      loop.stop()

    loop.run()
    check received == payload.len
    loop.close()

  test "bench_stream_pingpong":
    ## Round-trip a small message A → B → A, measure round-trips/sec.
    const Rounds = 20_000
    var count = 0
    var t0: int64 = 0
    let loop = newLoop()
    var a, b: IoStream
    (a, b) = newStreamPair(loop,
      onData = proc(s: IoStream, data: openArray[byte]) =
        # a end: a "pong" came back
        inc count
        if count >= Rounds:
          let elapsedUs = monoUs() - t0
          echo &"  bench_stream_pingpong  R={Rounds}  {elapsedUs}us  " &
               &"{Rounds * 1_000_000 div max(elapsedUs, 1)} rtt/s"
          a.close()
          b.close()
          loop.stop()
        else:
          discard a.write("ping")
      ,
      onData2 = proc(s: IoStream, data: openArray[byte]) =
        # b end: echo back
        discard b.write("pong")
    )

    discard loop.addTimer(10) do (id: int):
      t0 = monoUs()
      discard a.write("ping")

    discard loop.addTimer(10_000) do (id: int):
      doAssert false, "pingpong stalled at " & $count & " rounds"
      loop.stop()

    loop.run()
    check count == Rounds
    loop.close()

  test "bench_stream_many":
    ## 512 concurrent stream pairs, each pushing 8 KiB; aggregate B/s.
    const Pairs = 512
    const ChunkSize = 8192
    const Total = Pairs * ChunkSize
    var received: int64 = 0
    var t0: int64 = 0
    let loop = newLoop()
    var aEnds: seq[IoStream]
    var bEnds: seq[IoStream]
    aEnds.setLen(Pairs)
    bEnds.setLen(Pairs)
    for i in 0 ..< Pairs:
      (aEnds[i], bEnds[i]) = newStreamPair(loop,
        onData = proc(s: IoStream, data: openArray[byte]) =
          received += data.len
          if received >= Total:
            let elapsedUs = monoUs() - t0
            echo &"  bench_stream_many  P={Pairs} S={ChunkSize}  " &
                 &"{Total * 1_000_000 div max(elapsedUs, 1)} B/s"
            for j in 0 ..< Pairs:
              aEnds[j].close()
              bEnds[j].close()
            loop.stop()
      )

    discard loop.addTimer(10) do (id: int):
      t0 = monoUs()
      var chunk = newSeq[byte](ChunkSize)
      for i in 0 ..< Pairs:
        discard bEnds[i].write(chunk)

    discard loop.addTimer(10_000) do (id: int):
      doAssert false, "many-streams stalled at " & $received & " bytes"
      loop.stop()

    loop.run()
    check received == Total
    loop.close()

  test "bench_stream_small_writes":
    ## 8k × 1 KiB writes on one pair — stresses the queued-write + Write
    ## event flush path (no per-write buffering stalls).
    const Chunks = 8_192
    const ChunkSize = 1_024
    const Total = Chunks * ChunkSize
    var received: int64 = 0
    var t0: int64 = 0
    let loop = newLoop()
    var a, b: IoStream
    (a, b) = newStreamPair(loop,
      onData = proc(s: IoStream, data: openArray[byte]) =
        received += data.len
        if received >= Total:
          let elapsedUs = monoUs() - t0
          echo &"  bench_stream_small_writes  C={Chunks} S={ChunkSize}  " &
               &"{Total * 1_000_000 div max(elapsedUs, 1)} B/s"
          a.close()
          b.close()
          loop.stop()
    )

    discard loop.addTimer(10) do (id: int):
      t0 = monoUs()
      let chunk = "x".repeat(ChunkSize)
      for i in 0 ..< Chunks:
        let n = b.write(chunk)
        doAssert n == ChunkSize, "small write rejected at chunk " & $i

    discard loop.addTimer(10_000) do (id: int):
      doAssert false, "small writes stalled at " & $received & " bytes"
      loop.stop()

    loop.run()
    check received == Total
    loop.close()

  test "bench_stream_pause_churn":
    ## 500 pause → write → resume cycles on one pair: every resume must
    ## synchronously drain what was written, with no data loss.
    const Cycles = 500
    const ChunkSize = 1_024
    const Total = Cycles * ChunkSize
    var received: int64 = 0
    let loop = newLoop()
    var a, b: IoStream
    (a, b) = newStreamPair(loop,
      onData = proc(s: IoStream, data: openArray[byte]) =
        received += data.len
    )

    discard loop.addTimer(10) do (id: int):
      let chunk = "y".repeat(ChunkSize)
      let t0 = monoUs()
      for i in 0 ..< Cycles:
        a.pause()
        discard b.write(chunk)
        a.resume()
      let elapsedUs = monoUs() - t0
      echo &"  bench_stream_pause_churn  C={Cycles}  {elapsedUs}us  " &
           &"{Total * 1_000_000 div max(elapsedUs, 1)} B/s"
      a.close()
      b.close()
      loop.stop()

    discard loop.addTimer(10_000) do (id: int):
      loop.stop()

    loop.run()
    check received == Total
    loop.close()
