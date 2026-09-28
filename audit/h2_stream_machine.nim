## audit/h2_stream_machine.nim
##
## H2 stream-state enforcement vs out-of-order frames (RFC 7540 §5.1).
## Each violation class pins the exact server response; where the
## connection survives, a healthy follow-up request must still 200.
##
## Red: wrong code, missing RST, crash, or a poisoned connection.
## Green: exact codes below, follow-ups healthy.

import powpow
import powpow/proto/[http2, http2conn]
import ../tests/h2peer
import std/[tables, unittest]

proc smHandler(req: H2Request, res: H2Response) {.gcsafe.} =
  {.gcsafe.}:
    res.header("x-path", req.path).send(req.body)

proc smServer(port: int, loop: Loop): H2Server =
  result = newH2Server(loop, smHandler)
  result.listen("127.0.0.1", port)

suite "stream state machine enforcement":

  test "RST on idle stream is a connection error":
    let loop = newLoop()
    let srv = smServer(29212, loop)
    var peer: H2Peer
    loop.connect("127.0.0.1", 29212,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerSend(encodeRstStream(99, H2Cancelled))  # never opened
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
    check peer.gotGoaway
    check peer.goawayCode == H2ProtocolError

  test "RST on closed stream is silent, conn healthy":
    let loop = newLoop()
    let srv = smServer(29213, loop)
    var peer: H2Peer
    var phase = 0
    var followOk = false
    loop.connect("127.0.0.1", 29213,
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
          peer.peerSend(encodeRstStream(1, H2Cancelled))  # already closed
          peer.peerHeaders(3, "GET", "/after")
        elif phase == 1 and peer.respDone.getOrDefault(3, false):
          followOk = peer.respStatus(3) == "200" and not peer.gotGoaway
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
    check followOk

  test "DATA after END_STREAM resets the stream, conn healthy":
    let loop = newLoop()
    let srv = smServer(29214, loop)
    var peer: H2Peer
    var phase = 0
    var sawRst = false
    var followOk = false
    loop.connect("127.0.0.1", 29214,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "POST", "/up")  # endStream = true
        peer.peerSend(encodeFrame(0, 0, 1, @[byte('x')]))
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if phase == 0 and peer.streamReset.getOrDefault(1, false):
          phase = 1
          sawRst = true
          peer.peerHeaders(3, "GET", "/after")
        elif phase == 1 and peer.respDone.getOrDefault(3, false):
          followOk = peer.respStatus(3) == "200" and not peer.gotGoaway
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
    check sawRst
    check followOk

  test "trailer HEADERS without END_STREAM is a connection error":
    let loop = newLoop()
    let srv = smServer(29215, loop)
    var peer: H2Peer
    loop.connect("127.0.0.1", 29215,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "POST", "/up", endStream = false)
        # Trailer block on the open stream WITHOUT END_STREAM.
        peer.peerSend(encodeHeaders(1, peer.enc.encode(
          @[HpackHeader(name: "x-trailer", value: "1")]), false, true))
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
    check peer.gotGoaway
    check peer.goawayCode == H2ProtocolError

  test "WINDOW_UPDATE on idle stream is a connection error":
    let loop = newLoop()
    let srv = smServer(29216, loop)
    var peer: H2Peer
    loop.connect("127.0.0.1", 29216,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerSend(encodeWindowUpdate(77, 1024))  # never opened
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
    check peer.gotGoaway
    check peer.goawayCode == H2ProtocolError

  test "new stream after client GOAWAY is refused, old stream works":
    let loop = newLoop()
    let srv = smServer(29217, loop)
    var peer: H2Peer
    var phase = 0
    var refused = false
    var oldOk = false
    loop.connect("127.0.0.1", 29217,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "POST", "/open", endStream = false)
        peer.peerSend(encodeGoaway(0, H2NoError))
        peer.peerHeaders(3, "GET", "/new")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if phase == 0 and peer.streamReset.getOrDefault(3, false):
          phase = 1
          refused = true
          # Finish the pre-GOAWAY stream: body + END_STREAM.
          var body = newSeq[byte](4)
          body[0] = byte('d'); body[1] = byte('a')
          body[2] = byte('t'); body[3] = byte('a')
          peer.peerSend(encodeFrame(0, H2FlagEndStream, 1, body))
        elif phase == 1 and peer.respDone.getOrDefault(1, false):
          oldOk = peer.respStatus(1) == "200"
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
    check refused
    check oldOk
