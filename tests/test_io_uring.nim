## tests/test_io_uring.nim — Regression tests for the Linux io_uring backend.
##
## Compiled with `-d:powpowIoUring` (Linux) these exercise the submission-based
## code paths: batched/multishot accept, one-shot RECV/SEND, the synchronous-
## write fast path, the pending-buffer coalesce guard, and the retire path
## (closing a connection while its RECV is still in flight). On any other
## build the file is a no-op so the suite stays green everywhere.

import ../src/powpow
import std/unittest

when iouEnabled:

  # ── 1. Echo over keep-alive (accept + recv + sync write + re-arm) ───────────

  test "io_uring keep-alive echo (two requests, one connection)":
    var echoes = 0
    let loop = newLoop()
    let server = newTcpServer(loop,
      onData = proc(conn: Connection, data: openArray[byte]) =
        discard conn.send(data)
      ,
    )
    server.listen("127.0.0.1", 19980)

    discard loop.addTimer(40) do (id: int):
      loop.connect("127.0.0.1", 19980,
        onConnect = proc(conn: Connection) =
          discard conn.send("ping-1")
        ,
        onData = proc(conn: Connection, data: openArray[byte]) =
          if cast[string](data) == "ping-1":
            discard conn.send("ping-2")
          elif cast[string](data) == "ping-2":
            echoes = 2
            conn.close()
            loop.stop()
        ,
      )
    discard loop.addTimer(3000) do (id: int):
      server.close()
      loop.stop()

    loop.run()
    doAssert echoes == 2, "expected 2 echoes, got " & $echoes
    loop.close()

  # ── 2. Tiny SQ ring: ring-full defer/retry must not deadlock or corrupt ─────

  test "io_uring tiny ring (SQ-full deferral keeps working)":
    var echoed = ""
    let loop = newLoop(4)   # SQ ring of 4 entries — accepts/recv/send contend
    let server = newTcpServer(loop,
      onData = proc(conn: Connection, data: openArray[byte]) =
        discard conn.send(data)
      ,
    )
    server.listen("127.0.0.1", 19981)

    discard loop.addTimer(40) do (id: int):
      loop.connect("127.0.0.1", 19981,
        onConnect = proc(conn: Connection) =
          discard conn.send("sq-full")
        ,
        onData = proc(conn: Connection, data: openArray[byte]) =
          echoed = cast[string](data)
          conn.close()
          loop.stop()
        ,
      )
    discard loop.addTimer(3000) do (id: int):
      server.close()
      loop.stop()

    loop.run()
    doAssert echoed == "sq-full", "tiny-ring echo failed: " & echoed
    loop.close()

  # ── 3. Retire path: close a connection while its RECV is parked in flight ───
  #     Then immediately reuse the fd numbers with fresh connections; the
  #     retired buffer must not be re-pooled while the kernel op is pending.

  test "io_uring close-with-RECV-in-flight (retire) survives fd reuse":
    var parked: seq[Connection] = @[]
    var parkRound = 0
    var connected = 0
    var okEcho = 0

    let loop = newLoop()
    let server = newTcpServer(loop,
      onAccept = proc(conn: Connection) =
        parked.add(conn)
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        discard conn.send(data)
      ,
    )
    server.listen("127.0.0.1", 19982)

    proc parkClient() =
      loop.connect("127.0.0.1", 19982,
        onConnect = proc(conn: Connection) =
          parked.add(conn)     # client RECV is armed and parked here
          inc connected
        ,
        onData = proc(conn: Connection, data: openArray[byte]) =
          discard
        ,
      )

    discard loop.addTimer(30) do (id: int): parkClient()
    discard loop.addTimer(120) do (id: int):
      # Close every parked connection while its RECV is in flight → retire.
      for c in parked:
        c.close()
      parked.setLen(0)
      inc parkRound
      if parkRound < 3:
        discard loop.addTimer(10) do (id2: int): parkClient()
      else:
        # After the retire churn, verify a normal echo still works.
        discard loop.addTimer(10) do (id2: int):
          loop.connect("127.0.0.1", 19982,
            onConnect = proc(conn: Connection) =
              discard conn.send("post-retire")
            ,
            onData = proc(conn: Connection, data: openArray[byte]) =
              if cast[string](data) == "post-retire":
                okEcho = 1
                conn.close()
                loop.stop()
            ,
          )
    discard loop.addTimer(3000) do (id: int):
      server.close()
      loop.stop()

    loop.run()
    doAssert connected >= 4, "expected >= 4 park connects, got " & $connected
    doAssert okEcho == 1, "post-retire echo failed"
    loop.close()

  # ── 4. Large write + coalesce: two sends while a SEND op is in flight ───────
  #     Exercises pendingBuf (no appending to the in-flight writeBuf).

  test "io_uring large two-part write drains fully":
    const Part = 2 * 1024 * 1024
    var received = newSeq[byte](0)
    let loop = newLoop()
    let server = newTcpServer(loop,
      onData = proc(conn: Connection, data: openArray[byte]) =
        # Two back-to-back large sends; the second lands while the first SEND
        # op is (likely) still in flight.
        var big = newSeq[byte](Part)
        for i in 0 ..< Part: big[i] = byte(i and 0xFF)
        discard conn.send(big)
        discard conn.send(big)
      ,
    )
    server.listen("127.0.0.1", 19983)

    discard loop.addTimer(40) do (id: int):
      loop.connect("127.0.0.1", 19983,
        onConnect = proc(conn: Connection) =
          discard conn.send("go")
        ,
        onData = proc(conn: Connection, data: openArray[byte]) =
          received.add(data)
          if received.len >= Part * 2:
            conn.close()
            loop.stop()
        ,
      )
    discard loop.addTimer(5000) do (id: int):
      server.close()
      loop.stop()

    loop.run()
    doAssert received.len == Part * 2,
      "expected " & $(Part * 2) & " bytes, got " & $received.len
    var ok = true
    for i in 0 ..< Part:
      if received[i] != byte(i and 0xFF) or received[Part + i] != byte(i and 0xFF):
        ok = false
        break
    doAssert ok, "payload corruption in large two-part write"
    loop.close()

else:
  echo "io_uring tests skipped (backend not enabled)"

  import std/unittest
  test "skipped on non-io_uring":
    discard
