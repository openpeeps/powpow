## tests/test_http2.nim — h2c server loopback tests (RFC 7540).
##
## An in-loop H2 peer (raw frames via `loop.connect`, no threads) exercises
## `H2Server`: prior-knowledge handshake, request/response, multiplexing,
## CONTINUATION, flow control, Upgrade: h2c, PING, RST_STREAM, protocol
## errors, and GOAWAY.

import ../src/powpow
import ../src/powpow/proto/[http2, hpack, http2conn]
import std/[unittest, tables, base64, strutils]

const H2Magic = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

proc echoHandler(req: H2Request, res: H2Response) {.gcsafe.} =
  {.gcsafe.}:
    if req.path == "/fail":
      raise newException(CatchableError, "boom")
    res.header("x-path", req.path).send(req.body)

# ── In-loop test peer ─────────────────────────────────────────────────

type H2Peer = ref object
  conn: Connection
  parser: H2FrameParser
  enc, dec: HpackContext
  sendWindow: int32
  streamSend: Table[int32, int32]
  recvWindow: int32
  streamRecv: Table[int32, int32]
  respHeaders: Table[int32, seq[HpackHeader]]
  respBody: Table[int32, seq[byte]]
  respDone: Table[int32, bool]
  streamReset: Table[int32, bool]
  gotGoaway: bool
  goawayCode: H2ErrorCode
  pingAcked: bool
  pingOpaque: array[8, byte]
  queue: seq[tuple[sid: int32, data: seq[byte], off: int, fin: bool]]
  onFrame: proc(p: H2Peer, f: H2Frame) {.closure.}

proc newPeer(conn: Connection): H2Peer =
  H2Peer(conn: conn, parser: newH2FrameParser(),
         enc: newHpackContext(), dec: newHpackContext(),
         sendWindow: 65535, streamSend: initTable[int32, int32](),
         recvWindow: 65535, streamRecv: initTable[int32, int32](),
         respHeaders: initTable[int32, seq[HpackHeader]](),
         respBody: initTable[int32, seq[byte]](),
         respDone: initTable[int32, bool](),
         streamReset: initTable[int32, bool](),
         queue: @[])

proc peerSend(p: H2Peer, bytes: seq[byte]) =
  discard p.conn.send(bytes)

proc peerSendStr(p: H2Peer, s: string) =
  var b = newSeq[byte](s.len)
  for i, c in s: b[i] = byte(c)
  p.peerSend(b)

proc peerHeaders(p: H2Peer, sid: int32, meth, path: string,
                 endStream = true, endHeaders = true,
                 extra: seq[(string, string)] = @[]) =
  var hs = @[HpackHeader(name: ":method", value: meth),
             HpackHeader(name: ":scheme", value: "http"),
             HpackHeader(name: ":path", value: path),
             HpackHeader(name: ":authority", value: "127.0.0.1")]
  for (n, v) in extra:
    hs.add(HpackHeader(name: n, value: v))
  p.peerSend(encodeHeaders(sid, p.enc.encode(hs), endStream, endHeaders))
  p.streamSend[sid] = 65535
  p.streamRecv[sid] = 65535

proc peerBody(p: H2Peer, sid: int32, body: seq[byte], fin = true) =
  var off = 0
  while off < body.len:
    let avail = min([p.sendWindow, p.streamSend.getOrDefault(sid, 65535),
                     int32(16384)])
    if avail <= 0:
      p.queue.add((sid, body, off, fin))
      return
    let n = min(avail, int32(body.len - off))
    let last = off + int(n) == body.len and fin
    var flags: uint8 = 0
    if last: flags = flags or H2FlagEndStream
    p.peerSend(encodeFrame(0, flags, sid,
      body.toOpenArray(off, off + int(n) - 1)))
    p.sendWindow -= n
    p.streamSend[sid] = p.streamSend.getOrDefault(sid, 65535) - n
    off += int(n)

proc peerTopUp(p: H2Peer, sid: int32) =
  if p.recvWindow < 32768:
    let inc = uint32(65535 - int(p.recvWindow))
    p.recvWindow = 65535
    p.peerSend(encodeWindowUpdate(0, inc))
  let w = p.streamRecv.getOrDefault(sid, 65535)
  if w < 32768:
    let inc = uint32(65535 - int(w))
    p.streamRecv[sid] = 65535
    p.peerSend(encodeWindowUpdate(sid, inc))

proc peerFeed(p: H2Peer, data: openArray[byte]) =
  for f in p.parser.feed(data):
    if p.onFrame != nil:
      p.onFrame(p, f)
    case f.rawType
    of 4:  # SETTINGS
      if (f.flags and H2FlagAck) == 0:
        p.peerSend(encodeSettingsAck())
    of 1:  # HEADERS
      let hs = p.dec.decode(f.payload)
      if not p.respHeaders.hasKey(f.streamId):
        p.respHeaders[f.streamId] = @[]
      for h in hs: p.respHeaders[f.streamId].add(h)
      if (f.flags and H2FlagEndStream) != 0:
        p.respDone[f.streamId] = true
    of 0:  # DATA
      if not p.respBody.hasKey(f.streamId):
        p.respBody[f.streamId] = @[]
      for b in f.payload: p.respBody[f.streamId].add(b)
      p.recvWindow -= int32(f.payload.len)
      p.streamRecv[f.streamId] =
        p.streamRecv.getOrDefault(f.streamId, 65535) - int32(f.payload.len)
      p.peerTopUp(f.streamId)
      if (f.flags and H2FlagEndStream) != 0:
        p.respDone[f.streamId] = true
    of 8:  # WINDOW_UPDATE
      let inc = f.decodeWindowUpdate()
      if f.streamId == 0:
        p.sendWindow += int32(inc)
      else:
        p.streamSend[f.streamId] =
          p.streamSend.getOrDefault(f.streamId, 65535) + int32(inc)
      # Flush queued sends in order.
      while p.queue.len > 0:
        let (sid, data, off, fin) = p.queue[0]
        let avail = min([p.sendWindow, p.streamSend.getOrDefault(sid, 65535),
                         int32(16384)])
        if avail <= 0: break
        let n = min(avail, int32(data.len - off))
        let last = off + int(n) == data.len and fin
        var flags: uint8 = 0
        if last: flags = flags or H2FlagEndStream
        p.peerSend(encodeFrame(0, flags, sid,
          data.toOpenArray(off, off + int(n) - 1)))
        p.sendWindow -= n
        p.streamSend[sid] = p.streamSend.getOrDefault(sid, 65535) - n
        if off + int(n) >= data.len:
          p.queue.delete(0)
        else:
          p.queue[0] = (sid, data, off + int(n), fin)
          break
    of 6:  # PING
      if (f.flags and H2FlagAck) != 0:
        p.pingAcked = true
        p.pingOpaque = f.decodePing()
      else:
        p.peerSend(encodePingAck(f.decodePing()))
    of 7:  # GOAWAY
      let (_, code, _) = f.decodeGoaway()
      p.gotGoaway = true
      p.goawayCode = code
    of 3:  # RST_STREAM
      p.streamReset[f.streamId] = true
    else: discard

proc respStatus(p: H2Peer, sid: int32): string =
  for h in p.respHeaders.getOrDefault(sid, @[]):
    if h.name == ":status": return h.value
  ""

proc respHeader(p: H2Peer, sid: int32, name: string): string =
  for h in p.respHeaders.getOrDefault(sid, @[]):
    if h.name == name: return h.value
  ""

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
