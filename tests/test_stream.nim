## tests/test_stream.nim — Tests for powpow raw-fd streaming (IoStream).
##
## Tests: socketpair round-trip, large write backpressure, peer-close, read
## pause/resume, closeAfterWrite EOF, and writes to a closed peer.

import ../src/powpow
import std/[unittest, strutils]

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
