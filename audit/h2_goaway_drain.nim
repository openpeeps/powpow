## audit/h2_goaway_drain.nim
##
## H2 GOAWAY accuracy and post-GOAWAY discipline (RFC 7540 §6.8).
## lastStreamId must reflect the highest processed client stream;
## in-flight streams count; frames after teardown are discarded, never
## processed; no crash, no hang, no resurrection.
##
## Red: wrong lastSid, post-close processing, crash/hang.
## Green: exact behavior below.

import powpow
import powpow/proto/[http2, http2conn]
import ../tests/h2peer
import std/[tables, unittest]

proc gwHandler(req: H2Request, res: H2Response) {.gcsafe.} =
  {.gcsafe.}:
    res.header("x-path", req.path).send(req.body)

suite "goaway accuracy and discipline":

  test "GOAWAY lastStreamId is the highest processed stream":
    let loop = newLoop()
    let srv = newH2Server(loop, gwHandler)
    srv.listen("127.0.0.1", 29250)
    var peer: H2Peer
    var phase = 0
    var lastSid = -1i32
    var code = H2NoError
    loop.connect("127.0.0.1", 29250,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.onFrame = proc(p: H2Peer, f: H2Frame) {.closure.} =
          if f.rawType == 7:
            let (sid, c, _) = f.decodeGoaway()
            lastSid = sid
            code = c
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "GET", "/a")
        peer.peerHeaders(3, "GET", "/b")
        peer.peerHeaders(5, "GET", "/c")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if phase == 0 and peer.respDone.getOrDefault(5, false):
          phase = 1
          # All three done; protocol violation now: RST on idle stream 99.
          peer.peerSend(encodeRstStream(99, H2Cancelled))
        if peer.gotGoaway and phase == 1:
          phase = 2
          conn.close()
          srv.close()
          loop.stop()
      ,
    )
    discard loop.addTimer(8000) do (id: int):
      srv.close()
      loop.stop()
    loop.run()
    loop.close()
    check lastSid == 5
    check code == H2ProtocolError

  test "in-flight stream counts in lastStreamId":
    let loop = newLoop()
    let srv = newH2Server(loop, gwHandler)
    srv.listen("127.0.0.1", 29251)
    var peer: H2Peer
    var lastSid = -1i32
    loop.connect("127.0.0.1", 29251,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.onFrame = proc(p: H2Peer, f: H2Frame) {.closure.} =
          if f.rawType == 7:
            let (sid, _, _) = f.decodeGoaway()
            lastSid = sid
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "POST", "/open", endStream = false)
        # Stream 1 in flight (no END_STREAM); protocol violation now.
        peer.peerSend(encodeRstStream(99, H2Cancelled))
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if peer.gotGoaway:
          conn.close()
          srv.close()
          loop.stop()
      ,
    )
    discard loop.addTimer(8000) do (id: int):
      srv.close()
      loop.stop()
    loop.run()
    loop.close()
    check lastSid == 1

  test "frames after teardown are discarded, no resurrection":
    let loop = newLoop()
    let srv = newH2Server(loop, gwHandler)
    srv.listen("127.0.0.1", 29252)
    var peer: H2Peer
    var phase = 0
    var processedAfter = false
    loop.connect("127.0.0.1", 29252,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "GET", "/a")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if phase == 0 and peer.respDone.getOrDefault(1, false):
          phase = 1
          # Kill the connection server-side via idle-stream RST...
          peer.peerSend(encodeRstStream(99, H2Cancelled))
        elif phase == 1 and peer.gotGoaway:
          phase = 2
          # ...then keep speaking on the dead connection. Nothing may be
          # processed or answered; the socket is closed.
          peer.peerSend(encodeSettings(newSeq[H2Setting]()))
          peer.peerHeaders(3, "GET", "/late")
          discard loop.addTimer(500) do (id: int):
            processedAfter = peer.respDone.getOrDefault(3, false)
            conn.close()
            srv.close()
            loop.stop()
      ,
    )
    discard loop.addTimer(8000) do (id: int):
      srv.close()
      loop.stop()
    loop.run()
    loop.close()
    check peer.gotGoaway
    check not processedAfter
