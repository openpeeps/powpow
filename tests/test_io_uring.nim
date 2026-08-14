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

  proc bytesToString(data: openArray[byte]): string =
    ## Copy an openArray of bytes into a Nim string (a raw `cast` on an
    ## openArray is invalid — it is not a len-prefixed string/seq).
    result = newString(data.len)
    if data.len > 0:
      copyMem(addr result[0], unsafeAddr data[0], data.len)

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
          if bytesToString(data) == "ping-1":
            discard conn.send("ping-2")
          elif bytesToString(data) == "ping-2":
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
          echoed = bytesToString(data)
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

    proc closeRound() =
      # Close every parked connection while its RECV is in flight → retire.
      for c in parked:
        c.close()
      parked.setLen(0)
      inc parkRound
      if parkRound < 3:
        # Re-park a fresh client, then close again after it idles.
        discard loop.addTimer(15) do (id: int): parkClient()
        discard loop.addTimer(60) do (id: int): closeRound()
      else:
        # After the retire churn, verify a normal echo still works.
        discard loop.addTimer(10) do (id: int):
          loop.connect("127.0.0.1", 19982,
            onConnect = proc(conn: Connection) =
              discard conn.send("post-retire")
            ,
            onData = proc(conn: Connection, data: openArray[byte]) =
              if bytesToString(data) == "post-retire":
                okEcho = 1
                conn.close()
                loop.stop()
            ,
          )

    discard loop.addTimer(20) do (id: int): parkClient()
    discard loop.addTimer(100) do (id: int): closeRound()
    discard loop.addTimer(3000) do (id: int):
      server.close()
      loop.stop()

    loop.run()
    doAssert connected >= 3, "expected >= 3 park connects, got " & $connected
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

  # ── 5. Kernel feature probe: the ring must report per-opcode support and the
  #     IORING_FEAT_* bits surfaced by io_uring_setup.

  test "io_uring probe reports supported ops + features":
    let loop = newLoop()
    # Ops the backend always relies on must be present (or the probe unavailable,
    # in which case supportsOp() is permissive).
    doAssert loop.supportsOp(uring.IORING_OP_READ)
    doAssert loop.supportsOp(uring.IORING_OP_RECV)
    doAssert loop.supportsOp(uring.IORING_OP_SEND)
    doAssert loop.supportsOp(uring.IORING_OP_ACCEPT)
    doAssert loop.supportsOp(uring.IORING_OP_CONNECT)
    # IORING_FEAT_FAST_POLL is a kernel 5.7+ baseline; a modern kernel must
    # advertise it (and if it doesn't, hasFeature just returns false — no crash).
    discard loop.hasFeature(uring.IORING_FEAT_FAST_POLL)
    discard loop.hasFeature(uring.IORING_FEAT_EXT_ARG)
    loop.close()

  # ── 6. Shutdown-op ABI sanity: IORING_OP_SHUTDOWN is opcode 34, NOT the
  #     (nonexistent) SENDFILE 40 == MSG_RING. These constants are the binding
  #     layer's contract against linux/io_uring.h.

  test "io_uring opcode ABI constants":
    doAssert uring.IORING_OP_SEND_ZC == 47
    doAssert uring.IORING_OP_SENDMSG_ZC == 48
    doAssert uring.IORING_OP_SHUTDOWN == 34
    doAssert uring.IORING_OP_FILES_UPDATE == 20
    doAssert uring.IORING_OP_MSG_RING == 40
    doAssert uring.IORING_OP_CLOSE == 19
    doAssert uring.IORING_OP_SOCKET == 45
    # CQE flag bits are 1<<N (1<<0 is BUFFER, 1<<1 is MORE, 1<<3 is NOTIF).
    doAssert uring.IORING_CQE_F_BUFFER == 1
    doAssert uring.IORING_CQE_F_MORE == 2
    doAssert uring.IORING_CQE_F_SOCK_NONEMPTY == 4
    doAssert uring.IORING_CQE_F_NOTIF == 8

else:
  echo "io_uring tests skipped (backend not enabled)"

  import std/unittest
  test "skipped on non-io_uring":
    discard
