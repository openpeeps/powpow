## tests/test_http2.nim — h2c server loopback tests (RFC 7540).
##
## An in-loop H2 peer (raw frames via `loop.connect`, no threads) exercises
## `H2Server`: prior-knowledge handshake, request/response, multiplexing,
## CONTINUATION, flow control, Upgrade: h2c, PING, RST_STREAM, protocol
## errors, and GOAWAY.

import ../src/powpow
import ../src/powpow/proto/[http2, hpack, http2conn]
import std/[unittest, tables, base64, strutils]
import ./h2peer

proc echoHandler(req: H2Request, res: H2Response) {.gcsafe.} =
  {.gcsafe.}:
    if req.path == "/fail":
      raise newException(CatchableError, "boom")
    res.header("x-path", req.path).send(req.body)

# ── Test scaffolding ──────────────────────────────────────────────────

proc withServer(port: int, testBody: proc(srv: H2Server, loop: Loop)) =
  let loop = newLoop()
  let srv = newH2Server(loop, echoHandler)
  srv.listen("127.0.0.1", port)
  testBody(srv, loop)

proc watchdog(loop: Loop, srv: H2Server) =
  discard loop.addTimer(8000) do (id: int):
    srv.close()
    loop.stop()

# ── Tests ─────────────────────────────────────────────────────────────

test "h2c_prior_knowledge_get":
  withServer(29910) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    loop.connect("127.0.0.1", 29910,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "GET", "/")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if peer.respDone.getOrDefault(1, false):
          conn.close()
          srv.close()
          loop.stop()
      ,
    )
    watchdog(loop, srv)
    loop.run()
    check peer.respDone.getOrDefault(1, false)
    check peer.respStatus(1) == "200"
    check peer.respHeader(1, "x-path") == "/"
    check peer.respBody.getOrDefault(1, @[]).len == 0
    loop.close()

test "h2c_post_echo_8k":
  withServer(29911) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    var sent = newSeq[byte](8192)
    for i in 0 ..< sent.len: sent[i] = byte(i mod 251)
    loop.connect("127.0.0.1", 29911,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "POST", "/echo", endStream = false)
        peer.peerBody(1, sent)
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if peer.respDone.getOrDefault(1, false):
          conn.close()
          srv.close()
          loop.stop()
      ,
    )
    watchdog(loop, srv)
    loop.run()
    check peer.respStatus(1) == "200"
    check peer.respBody.getOrDefault(1, @[]) == sent
    loop.close()

test "h2c_multiplexed_streams":
  withServer(29912) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    loop.connect("127.0.0.1", 29912,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "GET", "/a")
        peer.peerHeaders(3, "GET", "/b")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if peer.respDone.getOrDefault(1, false) and
           peer.respDone.getOrDefault(3, false):
          conn.close()
          srv.close()
          loop.stop()
      ,
    )
    watchdog(loop, srv)
    loop.run()
    check peer.respStatus(1) == "200"
    check peer.respStatus(3) == "200"
    check peer.respHeader(1, "x-path") == "/a"
    check peer.respHeader(3, "x-path") == "/b"
    loop.close()

test "h2c_fragmented_headers_continuation":
  withServer(29913) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    loop.connect("127.0.0.1", 29913,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        let blk = peer.enc.encode(@[
          HpackHeader(name: ":method", value: "GET"),
          HpackHeader(name: ":scheme", value: "http"),
          HpackHeader(name: ":path", value: "/frag"),
          HpackHeader(name: ":authority", value: "127.0.0.1"),
          HpackHeader(name: "x-big", value: "0123456789abcdef")])
        # Split the block: HEADERS carries END_STREAM but no END_HEADERS.
        peer.peerSend(encodeFrame(1, H2FlagEndStream, 1,
          blk.toOpenArray(0, 4)))
        peer.peerSend(encodeFrame(9, H2FlagEndHeaders, 1,
          blk.toOpenArray(5, blk.len - 1)))
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if peer.respDone.getOrDefault(1, false):
          conn.close()
          srv.close()
          loop.stop()
      ,
    )
    watchdog(loop, srv)
    loop.run()
    check peer.respStatus(1) == "200"
    check peer.respHeader(1, "x-path") == "/frag"
    loop.close()

test "h2c_flow_control_100k_body":
  withServer(29914) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    var sent = newSeq[byte](100_000)
    for i in 0 ..< sent.len: sent[i] = byte((i * 7) mod 256)
    loop.connect("127.0.0.1", 29914,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "POST", "/echo", endStream = false)
        peer.peerBody(1, sent)  # chunks by windows, queues the rest
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if peer.respDone.getOrDefault(1, false):
          conn.close()
          srv.close()
          loop.stop()
      ,
    )
    watchdog(loop, srv)
    loop.run()
    check peer.respDone.getOrDefault(1, false)
    check peer.respStatus(1) == "200"
    let got = peer.respBody.getOrDefault(1, @[])
    check got.len == sent.len
    check got == sent
    loop.close()

test "h2c_upgrade_from_h1":
  withServer(29915) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    var raw101 = ""
    var got101 = false
    # HTTP2-Settings: HEADER_TABLE_SIZE = 4096.
    let pl = @[0x00'u8, 0x01, 0x00, 0x00, 0x10, 0x00]
    var b64 = base64.encode(cast[string](pl))
    b64 = b64.replace('+', '-').replace('/', '_')
    b64 = b64.strip(leading = false, trailing = true, chars = {'='})
    loop.connect("127.0.0.1", 29915,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        var b = "GET /up HTTP/1.1\r\nHost: 127.0.0.1\r\n" &
          "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n" &
          "HTTP2-Settings: " & b64 & "\r\n\r\n"
        var req = newSeq[byte](b.len)
        for i, c in b: req[i] = byte(c)
        peer.peerSend(req)
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        if not got101:
          raw101.add(cast[string](@data))
          let sep = raw101.find("\r\n\r\n")
          if sep >= 0:
            check raw101.startsWith("HTTP/1.1 101")
            got101 = true
            peer.peerSendStr(H2Magic)
            peer.peerHeaders(3, "GET", "/after-upgrade")
            # 101 and H2 frames can coalesce in one read: feed the tail.
            let tailStart = sep + 4
            if tailStart < raw101.len:
              var tail = newSeq[byte](raw101.len - tailStart)
              for i in 0 ..< tail.len:
                tail[i] = byte(raw101[tailStart + i])
              peer.peerFeed(tail)
          return
        peer.peerFeed(data)
        if peer.respDone.getOrDefault(1, false) and
           peer.respDone.getOrDefault(3, false):
          conn.close()
          srv.close()
          loop.stop()
      ,
    )
    watchdog(loop, srv)
    loop.run()
    check got101
    check peer.respStatus(1) == "200"  # upgraded request answered
    check peer.respHeader(1, "x-path") == "/up"
    check peer.respStatus(3) == "200"
    check peer.respHeader(3, "x-path") == "/after-upgrade"
    loop.close()

test "h2c_ping_roundtrip":
  withServer(29916) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    loop.connect("127.0.0.1", 29916,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerSend(encodePing([1'u8, 2, 3, 4, 5, 6, 7, 8]))
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if peer.pingAcked:
          conn.close()
          srv.close()
          loop.stop()
      ,
    )
    watchdog(loop, srv)
    loop.run()
    check peer.pingAcked
    check peer.pingOpaque == [1'u8, 2, 3, 4, 5, 6, 7, 8]
    loop.close()

test "h2c_rst_then_healthy_stream":
  withServer(29917) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    loop.connect("127.0.0.1", 29917,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "GET", "/cancelled", endStream = false)
        peer.peerSend(encodeRstStream(1, H2Cancelled))
        peer.peerHeaders(3, "GET", "/alive")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if peer.respDone.getOrDefault(3, false):
          conn.close()
          srv.close()
          loop.stop()
      ,
    )
    watchdog(loop, srv)
    loop.run()
    check peer.respStatus(3) == "200"
    check peer.respHeader(3, "x-path") == "/alive"
    check not peer.respDone.getOrDefault(1, false)
    loop.close()

test "h2c_data_on_idle_is_connection_error":
  withServer(29918) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    var closed = false
    loop.connect("127.0.0.1", 29918,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        var d = @[byte('x')]
        peer.peerSend(encodeData(1, d, endStream = true))
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
      ,
      onClose = proc(conn: Connection) =
        closed = true
        srv.close()
        loop.stop()
    )
    watchdog(loop, srv)
    loop.run()
    check peer.gotGoaway
    check peer.goawayCode == H2ProtocolError
    check closed
    loop.close()

test "h2c_handler_error_is_500":
  withServer(29919) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    loop.connect("127.0.0.1", 29919,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "GET", "/fail")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if peer.respDone.getOrDefault(1, false):
          conn.close()
          srv.close()
          loop.stop()
      ,
    )
    watchdog(loop, srv)
    loop.run()
    check peer.respStatus(1) == "500"
    loop.close()

test "h2c_server_close_sends_goaway":
  withServer(29920) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    var closed = false
    loop.connect("127.0.0.1", 29920,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "GET", "/bye")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if peer.respDone.getOrDefault(1, false):
          srv.close()  # GOAWAY + close; client sees both.
      ,
      onClose = proc(conn: Connection) =
        closed = true
        loop.stop()
    )
    watchdog(loop, srv)
    loop.run()
    check peer.respStatus(1) == "200"
    check peer.gotGoaway
    check peer.goawayCode == H2NoError
    check closed
    loop.close()
