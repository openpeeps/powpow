## audit/h2_frame_size.nim
##
## H2 frame-layer validation vs malformed/split frames (RFC 7540 §4-§6).
## Wrong lengths, oversize payloads, reserved-bit abuse, split arrivals,
## padding games, and unknown extension types. Fixed-length violations
## must GOAWAY with FRAME_SIZE_ERROR; reassembly must be exact; padding
## abuse must PROTOCOL_ERROR; extensions must be ignored safely.
##
## Red: wrong code, misparse, hang, or crash.
## Green: exact codes below + healthy follow-ups.

import powpow
import powpow/proto/[http2, http2conn]
import ../tests/h2peer
import std/[strutils, tables, unittest]

proc fsHandler(req: H2Request, res: H2Response) {.gcsafe.} =
  {.gcsafe.}:
    res.header("x-path", req.path).send(req.body)

proc fsServer(port: int, loop: Loop): H2Server =
  result = newH2Server(loop, fsHandler)
  result.listen("127.0.0.1", port)

suite "frame layer validation":

  test "64KB DATA frame is FRAME_SIZE_ERROR":
    let loop = newLoop()
    let srv = fsServer(29242, loop)
    var peer: H2Peer
    loop.connect("127.0.0.1", 29242,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "POST", "/up", endStream = false)
        var big = newSeq[byte](65536)
        for i in 0 ..< big.len: big[i] = byte('z')
        peer.peerSend(encodeFrame(0, 0, 1, big))
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
    check peer.goawayCode == H2FrameSizeError

  test "short PING is FRAME_SIZE_ERROR":
    let loop = newLoop()
    let srv = fsServer(29243, loop)
    var peer: H2Peer
    loop.connect("127.0.0.1", 29243,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerSend(encodeFrame(6, 0, 0, @[1'u8, 2, 3, 4]))
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
    check peer.goawayCode == H2FrameSizeError

  test "non-empty SETTINGS ACK is FRAME_SIZE_ERROR":
    let loop = newLoop()
    let srv = fsServer(29244, loop)
    var peer: H2Peer
    loop.connect("127.0.0.1", 29244,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerSend(encodeFrame(4, H2FlagAck, 0, @[0'u8, 0]))
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
    check peer.goawayCode == H2FrameSizeError

  test "split frame arrival reassembles exactly":
    let loop = newLoop()
    let srv = fsServer(29245, loop)
    var peer: H2Peer
    var phase = 0
    var followOk = false
    var frame: seq[byte]
    loop.connect("127.0.0.1", 29245,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "POST", "/up", endStream = false)
        var body = newSeq[byte](16384)
        for i in 0 ..< body.len: body[i] = byte('s')
        frame = encodeFrame(0, H2FlagEndStream, 1, body)
        # Header in two halves, payload in two halves.
        peer.peerSend(frame[0 .. 4])
        peer.peerSend(frame[5 .. 8])
        peer.peerSend(frame[9 .. 8192])
        peer.peerSend(frame[8193 .. ^1])
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if phase == 0 and peer.respDone.getOrDefault(1, false):
          phase = 1
          var got = ""
          for b in peer.respBody.getOrDefault(1, @[]): got.add(char(b))
          # fsHandler echoes the raw request body.
          check peer.respStatus(1) == "200"
          check got == repeat('s', 16384)
          peer.peerHeaders(3, "GET", "/after")
        elif phase == 1 and peer.respDone.getOrDefault(3, false):
          followOk = peer.respStatus(3) == "200"
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

  test "incomplete frame waits; other conns unaffected; completion works":
    # Frames are sequential per connection AND frame bytes must be
    # contiguous on the wire: nothing (not even our own SETTINGS ack) may
    # interleave a split frame, so the handshake completes before the
    # partial frame goes out. Pinned: the stall is per-connection (a second
    # conn gets full service meanwhile), nothing crashes or GOAWAYs, and
    # completing the frame later dispatches exactly. (Slow-dripping one
    # frame is the H2 analogue of H1 slowloris; the read timeout, not the
    # parser, bounds it.)
    let loop = newLoop()
    let srv = fsServer(29246, loop)
    var peer: H2Peer
    var peer2: H2Peer
    var phase = 0  # 0 handshake, 1 stalled, 2 completing
    var restSent = false
    var otherOk = false
    var completeOk = false
    var frame: seq[byte]
    loop.connect("127.0.0.1", 29246,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if phase == 0:
          # Handshake seen (our SETTINGS ack already flushed by peerFeed):
          # now send HEADERS + partial DATA contiguously, then stall.
          phase = 1
          peer.peerHeaders(1, "POST", "/up", endStream = false)
          var body = newSeq[byte](1024)
          for i in 0 ..< body.len: body[i] = byte('i')
          frame = encodeFrame(0, H2FlagEndStream, 1, body)
          peer.peerSend(frame[0 .. 108])  # header + 100 payload bytes; stall
          # Second connection must get full service meanwhile.
          loop.connect("127.0.0.1", 29246,
            onConnect = proc(conn2: Connection) =
              peer2 = newPeer(conn2)
              peer2.peerSendStr(H2Magic)
              peer2.peerSend(encodeSettings(newSeq[H2Setting]()))
              peer2.peerHeaders(1, "GET", "/other")
            ,
            onData = proc(conn2: Connection, data2: openArray[byte]) =
              peer2.peerFeed(data2)
              if peer2.respDone.getOrDefault(1, false):
                otherOk = peer2.respStatus(1) == "200"
                conn2.close()
                # Other conn served: complete the stalled frame now.
                if not restSent:
                  restSent = true
                  phase = 2
                  peer.peerSend(frame[109 .. ^1])
            ,
          )
        elif phase == 2 and peer.respDone.getOrDefault(1, false):
          var got = ""
          for b in peer.respBody.getOrDefault(1, @[]): got.add(char(b))
          completeOk = peer.respStatus(1) == "200" and
                       got == repeat('i', 1024) and not peer.gotGoaway
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
    check otherOk
    check completeOk

  test "valid padded HEADERS dispatches; over-pad is PROTOCOL_ERROR":
    # Subtest A: padded single-block request works.
    block subA:
      let loop = newLoop()
      let srv = fsServer(29247, loop)
      var peer: H2Peer
      var ok = false
      loop.connect("127.0.0.1", 29247,
        onConnect = proc(conn: Connection) =
          peer = newPeer(conn)
          peer.peerSendStr(H2Magic)
          peer.peerSend(encodeSettings(newSeq[H2Setting]()))
          var blk = peer.enc.encode(@[HpackHeader(name: ":method", value: "GET"),
            HpackHeader(name: ":scheme", value: "http"),
            HpackHeader(name: ":path", value: "/pad"),
            HpackHeader(name: ":authority", value: "127.0.0.1")])
          var payload = @[3'u8] & blk & @[0'u8, 0, 0]  # padLen 3 + 3 pad bytes
          peer.peerSend(encodeFrame(1, H2FlagEndHeaders or H2FlagEndStream or
                                    H2FlagPadded, 1, payload))
        ,
        onData = proc(conn: Connection, data: openArray[byte]) =
          peer.peerFeed(data)
          if peer.respDone.getOrDefault(1, false):
            ok = peer.respStatus(1) == "200" and not peer.gotGoaway
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
      check ok
    # Subtest B: pad length exceeds the payload.
    block subB:
      let loop = newLoop()
      let srv = fsServer(29248, loop)
      var peer: H2Peer
      loop.connect("127.0.0.1", 29248,
        onConnect = proc(conn: Connection) =
          peer = newPeer(conn)
          peer.peerSendStr(H2Magic)
          peer.peerSend(encodeSettings(newSeq[H2Setting]()))
          peer.peerSend(encodeFrame(1, H2FlagEndHeaders or H2FlagPadded,
                                    1, @[200'u8, 0x82]))
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

  test "unknown extension frames are ignored, conn healthy":
    let loop = newLoop()
    let srv = fsServer(29249, loop)
    var peer: H2Peer
    var followOk = false
    loop.connect("127.0.0.1", 29249,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerSend(encodeFrame(10, 0xFF, 0, @[1'u8, 2, 3]))  # unknown type
        peer.peerHeaders(1, "GET", "/after")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if peer.respDone.getOrDefault(1, false):
          followOk = peer.respStatus(1) == "200" and not peer.gotGoaway
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
