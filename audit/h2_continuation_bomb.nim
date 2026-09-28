## audit/h2_continuation_bomb.nim
##
## H2 CONTINUATION-fragment buffering vs a multi-KB header block.
## `fragBuf` used to accumulate every CONTINUATION until END_HEADERS; the
## `maxHeaderList` (16 KB) check ran only AFTER the full block decoded —
## so a peer forced the server to buffer megabytes per stream before any
## size gate engaged (slow-stream it and the RAM is held indefinitely).
##
## Fix: CONTINUATION bytes are accounted against maxHeaderList + one frame
## of slop incrementally; excess is refused with COMPRESSION_ERROR
## (RFC 7540 §4.3) without buffering further.
##
## Red: deep bomb inflates RSS ~1:1 and/or the trip stream never RSTs.
## Green: RSS stays flat, over-budget block RSTs early, conn stays healthy.

import powpow
import powpow/proto/[http2, http2conn]
import ../tests/h2peer
import std/[strutils, tables, unittest]

when defined(linux):
  proc bombRssKB(): int =
    for line in readFile("/proc/self/status").splitLines():
      if line.startsWith("VmRSS:"):
        return parseInt(line.splitWhitespace()[1])
    return 0

proc bombHandler(req: H2Request, res: H2Response) {.gcsafe.} =
  {.gcsafe.}:
    res.header("x-path", req.path).send(req.body)

const
  BombPort = 29211
  FragSize = 16384
  DeepFrags = 40  # 640 KB block: far past the ~32 KB budget

suite "continuation fragment buffering is bounded":

  test "deep bomb stays flat, over-budget block RSTs early":
    let loop = newLoop()
    let srv = newH2Server(loop, bombHandler)
    srv.listen("127.0.0.1", BombPort)

    var frag = newSeq[byte](FragSize)
    for i in 0 ..< frag.len: frag[i] = 0xFF  # invalid HPACK
    var baseline = 0
    var rstB = false
    var followB = false

    # Phase 1 (conn A): depth — 40 CONTINUATIONs + END_HEADERS.
    var peerA: H2Peer
    var phaseA = 0
    loop.connect("127.0.0.1", BombPort,
      onConnect = proc(conn: Connection) =
        peerA = newPeer(conn)
        peerA.peerSendStr(H2Magic)
        peerA.peerSend(encodeSettings(newSeq[H2Setting]()))
        peerA.peerHeaders(1, "GET", "/warm")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peerA.peerFeed(data)
        if phaseA == 0 and peerA.respDone.getOrDefault(1, false):
          phaseA = 1
          when defined(linux):
            GC_fullCollect()
            baseline = bombRssKB()
          peerA.peerSend(encodeHeaders(3, @[0x82'u8], false, false))
          for i in 0 ..< DeepFrags:
            var flags: uint8 = 0
            if i == DeepFrags - 1: flags = flags or H2FlagEndHeaders
            peerA.peerSend(encodeFrame(9, flags, 3, frag))
        elif phaseA == 1 and (peerA.streamReset.getOrDefault(3, false) or
                              peerA.gotGoaway):
          # Bomb stream over (RST post-fix; RST-at-END_HEADERS pre-fix).
          phaseA = 2
          conn.close()
          # Phase 2 (conn B): trip — HEADERS + 2 CONTINUATIONs, no END_HEADERS.
          # Budget (~32 KB) trips on the 2nd CONTINUATION post-fix.
          var peerB: H2Peer
          var phaseB = 0
          loop.connect("127.0.0.1", BombPort,
            onConnect = proc(conn2: Connection) =
              peerB = newPeer(conn2)
              peerB.peerSendStr(H2Magic)
              peerB.peerSend(encodeSettings(newSeq[H2Setting]()))
              peerB.peerSend(encodeHeaders(1, @[0x82'u8], false, false))
              peerB.peerSend(encodeFrame(9, 0, 1, frag))
              peerB.peerSend(encodeFrame(9, 0, 1, frag))
            ,
            onData = proc(conn2: Connection, data2: openArray[byte]) =
              peerB.peerFeed(data2)
              if phaseB == 0 and peerB.streamReset.getOrDefault(1, false):
                phaseB = 1
                rstB = true
                peerB.peerHeaders(3, "GET", "/after")
              elif phaseB == 1 and peerB.respDone.getOrDefault(3, false):
                followB = peerB.respStatus(3) == "200"
                conn2.close()
                srv.close()
                loop.stop()
            ,
          )
      ,
    )
    discard loop.addTimer(30000) do (id: int):
      srv.close()
      loop.stop()
    loop.run()
    loop.close()

    check rstB
    check followB
    when defined(linux):
      let growth = bombRssKB() - baseline
      echo "    continuation bomb: RSS growth ", growth, " KB for ",
        (DeepFrags * FragSize) div 1024, " KB of fragments"
      check growth < 256
