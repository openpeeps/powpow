## audit/h2_flood_policy.nim
##
## H2 control-frame flood behavior (RFC 7540 §6.5/§6.7/§10.5).
##
## FINDING (accepted with limits, see below): the server has no generic
## rate limiter — every PING/SETTINGS/RST/WINDOW_UPDATE is processed and
## (where required) acked 1:1. That matches the cost profile of any
## request/response protocol (no amplification), and each vector below is
## bounded by an existing cap. The residual risk is CPU-for-packets at
## line rate, identical to an H1 GET flood.
##
## Proposed limits (not yet implemented; see REPORT.md):
##   - PING: max ~100 un-acked... (no RTT signal; instead) count PINGs per
##     connection and GOAWAY(ENHANCE_YOUR_CALM) past 10k lifetime — legit
##     health checks never approach it.
##   - SETTINGS: same 10k lifetime budget (each is acked + applied).
##   - RST on missing/closed streams: already O(1) silent; no limit needed.
##   - Stream open/RST churn: bounded by maxConcurrentLocal (128) — the
##     Rapid-Reset shape cannot exceed 128 live streams; each RST is O(1).
##
## Red: superlinear cost, missing ack, dead connection, or cap bypass.
## Green: 1:1 bounded handling + healthy follow-ups (policy pins).

import powpow
import powpow/proto/[http2, http2conn]
import ../tests/h2peer
import std/[monotimes, tables, times, unittest]

proc flHandler(req: H2Request, res: H2Response) {.gcsafe.} =
  {.gcsafe.}:
    res.header("x-path", req.path).send(req.body)

suite "control-frame floods stay 1:1 and bounded":

  test "5k PINGs all acked, conn healthy":
    let loop = newLoop()
    let srv = newH2Server(loop, flHandler)
    srv.listen("127.0.0.1", 29218)
    var peer: H2Peer
    var acks = 0
    var followOk = false
    let t0 = getMonoTime()
    loop.connect("127.0.0.1", 29218,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        # Count every PING ACK frame (a bool flag would collapse a batch).
        peer.onFrame = proc(p: H2Peer, f: H2Frame) {.closure.} =
          if f.rawType == 6 and (f.flags and H2FlagAck) != 0:
            inc acks
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        var opaque: array[8, byte]
        for i in 0 ..< 5000:
          opaque[0] = byte(i and 0xFF)
          opaque[1] = byte((i shr 8) and 0xFF)
          peer.peerSend(encodePing(opaque))
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if acks >= 5000 and not followOk:
          peer.peerHeaders(1, "GET", "/after")
        if peer.respDone.getOrDefault(1, false):
          followOk = peer.respStatus(1) == "200" and not peer.gotGoaway
          conn.close()
          srv.close()
          loop.stop()
      ,
    )
    discard loop.addTimer(30000) do (id: int):
      srv.close()
      loop.stop()
    loop.run()
    loop.close()
    let ms = (getMonoTime() - t0).inMilliseconds
    echo "    5k PINGs acked in ", ms, " ms"
    check acks == 5000
    check followOk

  test "5k empty SETTINGS all acked, conn healthy":
    let loop = newLoop()
    let srv = newH2Server(loop, flHandler)
    srv.listen("127.0.0.1", 29219)
    var peer: H2Peer
    var ackCount = 0
    var followOk = false
    loop.connect("127.0.0.1", 29219,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        for _ in 0 ..< 5000:
          peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        # Count acks via onFrame hook below.
        peer.onFrame = proc(p: H2Peer, f: H2Frame) {.closure.} =
          if f.rawType == 4 and (f.flags and H2FlagAck) != 0:
            inc ackCount
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if ackCount >= 5000 and not followOk:
          peer.peerHeaders(1, "GET", "/after")
        if peer.respDone.getOrDefault(1, false):
          followOk = peer.respStatus(1) == "200" and not peer.gotGoaway
          conn.close()
          srv.close()
          loop.stop()
      ,
    )
    discard loop.addTimer(30000) do (id: int):
      srv.close()
      loop.stop()
    loop.run()
    loop.close()
    check ackCount == 5000
    check followOk

  test "5k RSTs on closed streams are silent, conn healthy":
    let loop = newLoop()
    let srv = newH2Server(loop, flHandler)
    srv.listen("127.0.0.1", 29220)
    var peer: H2Peer
    var phase = 0
    var followOk = false
    loop.connect("127.0.0.1", 29220,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "GET", "/first")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if phase == 0 and peer.respDone.getOrDefault(1, false):
          phase = 1
          for i in 0 ..< 5000:
            peer.peerSend(encodeRstStream(1, H2Cancelled))  # closed already
          peer.peerHeaders(3, "GET", "/after")
        elif phase == 1 and peer.respDone.getOrDefault(3, false):
          followOk = peer.respStatus(3) == "200" and not peer.gotGoaway and
                     peer.streamReset.len == 0
          conn.close()
          srv.close()
          loop.stop()
      ,
    )
    discard loop.addTimer(30000) do (id: int):
      srv.close()
      loop.stop()
    loop.run()
    loop.close()
    check followOk

  test "open/RST churn within concurrency cap stays healthy":
    # Rapid-Reset shape: fill the 128-stream window, reset all, repeat, then
    # a follow-up on a fresh stream. Client RSTs are silent server-side, so
    # the observable is openCount draining: if any RST failed to release its
    # stream, the window stays full and the follow-up is REFUSED.
    let loop = newLoop()
    let srv = newH2Server(loop, flHandler)
    srv.listen("127.0.0.1", 29221)
    var peer: H2Peer
    var followSid = 0i32
    var followOk = false
    loop.connect("127.0.0.1", 29221,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        var sid = 1i32
        for _ in 0 ..< 4:
          for _ in 0 ..< 128:
            peer.peerHeaders(sid, "POST", "/churn", endStream = false)
            peer.peerSend(encodeRstStream(sid, H2Cancelled))
            sid += 2
        followSid = sid
        peer.peerHeaders(sid, "GET", "/after")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if peer.respDone.getOrDefault(followSid, false):
          followOk = peer.respStatus(followSid) == "200" and
                     not peer.streamReset.getOrDefault(followSid, false)
          conn.close()
          srv.close()
          loop.stop()
      ,
    )
    discard loop.addTimer(30000) do (id: int):
      srv.close()
      loop.stop()
    loop.run()
    loop.close()
    check followOk
