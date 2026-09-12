## tests/test_http2_security.nim — HTTP/2 abuse tests (RFC 7540 §5–§7, §10).
##
## Malformed handshakes, frames, header blocks, settings, and flow-control
## attacks against `H2Server` via the shared in-loop peer: stream errors
## must stay contained (RST + healthy follow-up) and connection errors
## must end in GOAWAY with the right code.

import ../src/powpow
import ../src/powpow/proto/[http2, hpack, http2conn]
import ./h2peer
import std/[unittest, tables, strutils]

proc secHandler(req: H2Request, res: H2Response) {.gcsafe.} =
  {.gcsafe.}:
    res.header("x-path", req.path).send(req.body)

proc secServer(port: int, loop: Loop,
               maxConcurrent = H2DefaultMaxConcurrent,
               maxHeaderList = H2DefaultMaxHeaderList,
               maxBody = H2DefaultMaxBody): H2Server =
  let srv = newH2Server(loop, secHandler, maxConcurrent, maxHeaderList,
                        maxBody)
  srv.listen("127.0.0.1", port)
  srv

proc secRun(loop: Loop, srv: H2Server) =
  h2watchdog(loop, srv)
  loop.run()

proc openPeer(loop: Loop, port: int): H2Peer =
  var peer: H2Peer
  loop.connect("127.0.0.1", port,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodeSettings(newSeq[H2Setting]()))
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      peer.peerFeed(data)
    ,
  )
  peer

test "sec_oversize_headers_431_and_healthy":
  let loop = newLoop()
  let srv = secServer(29950, loop, maxHeaderList = 100)
  var peer: H2Peer
  var done431 = false
  var doneOk = false
  loop.connect("127.0.0.1", 29950,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodeSettings(newSeq[H2Setting]()))
      var big = ""
      for i in 0 ..< 200: big.add('a')
      peer.peerHeaders(1, "GET", "/big", extra = @[("x-big", big)])
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      peer.peerFeed(data)
      if peer.respDone.getOrDefault(1, false) and not done431:
        done431 = true
        peer.peerHeaders(3, "GET", "/small")
      if peer.respDone.getOrDefault(3, false):
        doneOk = true
        conn.close()
        srv.close()
        loop.stop()
    ,
  )
  secRun(loop, srv)
  check done431
  check peer.respStatus(1) == "431"
  check doneOk
  check peer.respStatus(3) == "200"
  loop.close()

test "sec_uppercase_header_name_rst":
  let loop = newLoop()
  let srv = secServer(29951, loop)
  var peer: H2Peer
  var sawRst = false
  var doneOk = false
  loop.connect("127.0.0.1", 29951,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodeSettings(newSeq[H2Setting]()))
      let blk = peer.enc.encode(@[
        HpackHeader(name: ":method", value: "GET"),
        HpackHeader(name: ":scheme", value: "http"),
        HpackHeader(name: ":path", value: "/upper"),
        HpackHeader(name: ":authority", value: "127.0.0.1"),
        HpackHeader(name: "X-Custom", value: "v")])
      peer.peerSend(encodeHeaders(1, blk, endStream = true))
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      peer.peerFeed(data)
      if peer.streamReset.getOrDefault(1, false) and not sawRst:
        sawRst = true
        peer.peerHeaders(3, "GET", "/after")
      if peer.respDone.getOrDefault(3, false):
        doneOk = true
        conn.close()
        srv.close()
        loop.stop()
    ,
  )
  secRun(loop, srv)
  check sawRst
  check doneOk
  check peer.respStatus(3) == "200"
  loop.close()

test "sec_missing_pseudo_header_rst":
  let loop = newLoop()
  let srv = secServer(29952, loop)
  var peer: H2Peer
  var sawRst = false
  var doneOk = false
  loop.connect("127.0.0.1", 29952,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodeSettings(newSeq[H2Setting]()))
      let blk = peer.enc.encode(@[
        HpackHeader(name: ":method", value: "GET"),
        HpackHeader(name: ":scheme", value: "http")])
      peer.peerSend(encodeHeaders(1, blk, endStream = true))
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      peer.peerFeed(data)
      if peer.streamReset.getOrDefault(1, false) and not sawRst:
        sawRst = true
        peer.peerHeaders(3, "GET", "/after")
      if peer.respDone.getOrDefault(3, false):
        doneOk = true
        conn.close()
        srv.close()
        loop.stop()
    ,
  )
  secRun(loop, srv)
  check sawRst
  check doneOk
  loop.close()

test "sec_connection_header_rst":
  let loop = newLoop()
  let srv = secServer(29953, loop)
  var peer: H2Peer
  var sawRst = false
  var doneOk = false
  loop.connect("127.0.0.1", 29953,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodeSettings(newSeq[H2Setting]()))
      peer.peerHeaders(1, "GET", "/conn",
                       extra = @[("connection", "keep-alive")])
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      peer.peerFeed(data)
      if peer.streamReset.getOrDefault(1, false) and not sawRst:
        sawRst = true
        peer.peerHeaders(3, "GET", "/after")
      if peer.respDone.getOrDefault(3, false):
        doneOk = true
        conn.close()
        srv.close()
        loop.stop()
    ,
  )
  secRun(loop, srv)
  check sawRst
  check doneOk
  loop.close()

test "sec_push_promise_is_goaway":
  let loop = newLoop()
  let srv = secServer(29954, loop)
  var peer: H2Peer
  var closed = false
  loop.connect("127.0.0.1", 29954,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodeSettings(newSeq[H2Setting]()))
      peer.peerSend(encodeFrame(5, 0, 1, [0x00'u8, 0x01, 0x02, 0x03]))
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      peer.peerFeed(data)
    ,
    onClose = proc(conn: Connection) =
      closed = true
      srv.close()
      loop.stop()
  )
  secRun(loop, srv)
  check peer.gotGoaway
  check peer.goawayCode == H2ProtocolError
  check closed
  loop.close()

test "sec_plain_h1_gets_426_and_garbage_closed":
  let loop = newLoop()
  let srv = secServer(29955, loop)
  var raw = ""
  var closed1 = false
  var closed2 = false
  loop.connect("127.0.0.1", 29955,
    onConnect = proc(conn: Connection) =
      discard conn.send("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      raw.add(cast[string](@data))
    ,
    onClose = proc(conn: Connection) =
      closed1 = true
      loop.connect("127.0.0.1", 29955,
        onConnect = proc(conn2: Connection) =
          discard conn2.send("ZZZZZZZZ")
        ,
        onData = proc(conn2: Connection, data: openArray[byte]) =
          raw.add("UNEXPECTED-DATA")
        ,
        onClose = proc(conn2: Connection) =
          closed2 = true
          srv.close()
          loop.stop()
      )
  )
  secRun(loop, srv)
  check raw.startsWith("HTTP/1.1 426")
  check raw.contains("Upgrade: h2c")
  check not raw.contains("UNEXPECTED-DATA")
  check closed1
  check closed2
  loop.close()

test "sec_first_frame_not_settings_goaway":
  let loop = newLoop()
  let srv = secServer(29956, loop)
  var peer: H2Peer
  var closed = false
  loop.connect("127.0.0.1", 29956,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodePing([1'u8, 2, 3, 4, 5, 6, 7, 8]))
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      peer.peerFeed(data)
    ,
    onClose = proc(conn: Connection) =
      closed = true
      srv.close()
      loop.stop()
  )
  secRun(loop, srv)
  check peer.gotGoaway
  check peer.goawayCode == H2ProtocolError
  check closed
  loop.close()

test "sec_stray_continuation_goaway":
  let loop = newLoop()
  let srv = secServer(29957, loop)
  var peer: H2Peer
  var closed = false
  loop.connect("127.0.0.1", 29957,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodeSettings(newSeq[H2Setting]()))
      peer.peerSend(encodeFrame(9, H2FlagEndHeaders, 1, [0x88'u8]))
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      peer.peerFeed(data)
    ,
    onClose = proc(conn: Connection) =
      closed = true
      srv.close()
      loop.stop()
  )
  secRun(loop, srv)
  check peer.gotGoaway
  check peer.goawayCode == H2ProtocolError
  check closed
  loop.close()

test "sec_zero_window_update_goaway":
  let loop = newLoop()
  let srv = secServer(29958, loop)
  var peer: H2Peer
  var closed = false
  loop.connect("127.0.0.1", 29958,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodeSettings(newSeq[H2Setting]()))
      peer.peerSend(encodeFrame(8, 0, 0, [0'u8, 0, 0, 0]))
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      peer.peerFeed(data)
    ,
    onClose = proc(conn: Connection) =
      closed = true
      srv.close()
      loop.stop()
  )
  secRun(loop, srv)
  check peer.gotGoaway
  check peer.goawayCode == H2ProtocolError
  check closed
  loop.close()

test "sec_huge_window_update_goaway":
  let loop = newLoop()
  let srv = secServer(29959, loop)
  var peer: H2Peer
  var closed = false
  loop.connect("127.0.0.1", 29959,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodeSettings(newSeq[H2Setting]()))
      peer.peerSend(encodeFrame(8, 0, 0, [0x7F'u8, 0xFF, 0xFF, 0xFF]))
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      peer.peerFeed(data)
    ,
    onClose = proc(conn: Connection) =
      closed = true
      srv.close()
      loop.stop()
  )
  secRun(loop, srv)
  check peer.gotGoaway
  check peer.goawayCode == H2FlowControlError
  check closed
  loop.close()

test "sec_bad_settings_goaway":
  let loop = newLoop()
  let srv = secServer(29960, loop)
  var peer: H2Peer
  var closed = false
  loop.connect("127.0.0.1", 29960,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      # MAX_FRAME_SIZE = 100 (below the 16384 minimum).
      peer.peerSend(encodeFrame(4, 0, 0,
        [0x00'u8, 0x05, 0x00, 0x00, 0x00, 0x64]))
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      peer.peerFeed(data)
    ,
    onClose = proc(conn: Connection) =
      closed = true
      srv.close()
      loop.stop()
  )
  secRun(loop, srv)
  check peer.gotGoaway
  check peer.goawayCode == H2ProtocolError
  check closed
  loop.close()

test "sec_table_size_update_over_limit_rst":
  let loop = newLoop()
  let srv = secServer(29961, loop)
  var peer: H2Peer
  var sawRst = false
  var doneOk = false
  loop.connect("127.0.0.1", 29961,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodeSettings(newSeq[H2Setting]()))
      # Table size update to 8192 (over the 4096 protocol limit).
      peer.peerSend(encodeFrame(1, H2FlagEndHeaders or H2FlagEndStream, 1,
        [0x3F'u8, 0xE1, 0x3F, 0x82, 0x86, 0x84]))
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      peer.peerFeed(data)
      if peer.streamReset.getOrDefault(1, false) and not sawRst:
        sawRst = true
        peer.peerHeaders(3, "GET", "/after")
      if peer.respDone.getOrDefault(3, false):
        doneOk = true
        conn.close()
        srv.close()
        loop.stop()
    ,
  )
  secRun(loop, srv)
  check sawRst
  check doneOk
  check peer.respStatus(3) == "200"
  loop.close()

test "sec_body_over_max_body_rst":
  let loop = newLoop()
  let srv = secServer(29962, loop, maxBody = 1024)
  var peer: H2Peer
  var sawRst = false
  var doneOk = false
  var big = newSeq[byte](2048)
  for i in 0 ..< big.len: big[i] = byte('a')
  loop.connect("127.0.0.1", 29962,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodeSettings(newSeq[H2Setting]()))
      peer.peerHeaders(1, "POST", "/up", endStream = false)
      peer.peerBody(1, big)
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      peer.peerFeed(data)
      if peer.streamReset.getOrDefault(1, false) and not sawRst:
        sawRst = true
        peer.peerHeaders(3, "GET", "/after")
      if peer.respDone.getOrDefault(3, false):
        doneOk = true
        conn.close()
        srv.close()
        loop.stop()
    ,
  )
  secRun(loop, srv)
  check sawRst
  check doneOk
  check peer.respStatus(3) == "200"
  loop.close()

test "sec_max_concurrent_refused":
  let loop = newLoop()
  let srv = secServer(29963, loop, maxConcurrent = 1)
  var peer: H2Peer
  var done1 = false
  loop.connect("127.0.0.1", 29963,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodeSettings(newSeq[H2Setting]()))
      peer.peerHeaders(1, "GET", "/first", endStream = false)
      peer.peerHeaders(3, "GET", "/second")
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      peer.peerFeed(data)
      if peer.streamReset.getOrDefault(3, false) and not done1:
        # Second stream refused; finish the first with empty DATA.
        peer.peerSend(encodeFrame(0, H2FlagEndStream, 1, []))
      if peer.respDone.getOrDefault(1, false):
        done1 = true
        conn.close()
        srv.close()
        loop.stop()
    ,
  )
  secRun(loop, srv)
  check peer.streamReset.getOrDefault(3, false)
  check done1
  check peer.respStatus(1) == "200"
  loop.close()
