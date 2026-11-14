## tests/test_http2_streams.nim — H2 Phase 1C: streaming bodies, spill,
## per-stream timeouts, extended CONNECT, H2Server drain, flow-control
## autotune, request accessors, sendFile/sendError.

import ../src/powpow
import ../src/powpow/proto/[http2, hpack, http2conn]
import std/[unittest, tables, base64, strutils, os]
import ./h2peer

proc streamHandler(req: H2Request, res: H2Response) {.gcsafe.} =
  {.gcsafe.}:
    case req.path
    of "/stream":
      res.sendHeaders()
      res.sendChunk("aa")
      res.sendChunk("bb")
      res.finish()
    of "/sendfile":
      res.sendFile(req.getHeaderValue("x-file"))
    of "/error":
      res.sendError(404, "nope")
    of "/accessors":
      doAssert req.getMethod() == "get", req.getMethod()
      doAssert req.getPath() == "/accessors"
      doAssert req.getQuery() == "q=1"
      doAssert req.getScheme() == "http"
      doAssert req.getAuthority() == "127.0.0.1"
      doAssert req.getHeaderValue("X-Test") == "yes"
      doAssert req.getBodyString() == "hi"
      doAssert req.getClientIp() == "127.0.0.1"
      res.status(200).send("ok")
    of "/connect":
      # Extended-CONNECT probe: echo the negotiated protocol.
      res.status(200).send("proto=" & req.protocol & " meth=" & req.meth)
    else:
      # Spill-aware echo (production pattern for big uploads).
      if req.streamPath.len > 0:
        let data = readFile(req.streamPath)
        try:
          removeFile(req.streamPath)
        except OSError:
          discard
        res.status(200).send(data)
      else:
        res.status(200).send(req.body)

proc withServer(port: int, testBody: proc(srv: H2Server, loop: Loop)) =
  let loop = newLoop()
  let srv = newH2Server(loop, streamHandler)
  srv.listen("127.0.0.1", port)
  testBody(srv, loop)

proc watchdog(loop: Loop, srv: H2Server, ms = 8000) =
  discard loop.addTimer(ms) do (id: int):
    srv.close()
    loop.stop()

# ── C1a: response streaming ──────────────────────────────────────────────────

test "h2_streamed_response":
  withServer(30101) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    loop.connect("127.0.0.1", 30101,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "GET", "/stream")
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
    check peer.respHeader(1, "content-length") == ""  # streaming: no length
    var body = ""
    for b in peer.respBody.getOrDefault(1, @[]):
      body.add(char(b))
    check body == "aabb"
    loop.close()

test "h2_stream_finish_from_timer":
  let loop = newLoop()
  var held: H2Response
  let srv = newH2Server(loop, proc(req: H2Request,
                                   res: H2Response) {.gcsafe, closure.} =
    {.gcsafe.}:
      held = res
      res.sendHeaders()
  )
  srv.listen("127.0.0.1", 30102)
  var peer: H2Peer
  loop.connect("127.0.0.1", 30102,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodeSettings(newSeq[H2Setting]()))
      peer.peerHeaders(1, "GET", "/x")
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      peer.peerFeed(data)
      if peer.respDone.getOrDefault(1, false):
        conn.close()
        srv.close()
        loop.stop()
    ,
  )
  # The handler returned with the stream open (no 500): finish later.
  discard loop.addTimer(100) do (id: int):
    if held != nil:
      held.sendChunk("late")
      held.finish()
  watchdog(loop, srv)
  loop.run()
  check peer.respStatus(1) == "200"
  var body = ""
  for b in peer.respBody.getOrDefault(1, @[]):
    body.add(char(b))
  check body == "late"
  loop.close()

# ── C1b: request spill ───────────────────────────────────────────────────────

test "h2_request_spill_and_buffered":
  withServer(30103) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    var small = newSeq[byte](100)
    for i in 0 ..< small.len: small[i] = byte(i)
    var big = newSeq[byte](100_000)
    for i in 0 ..< big.len: big[i] = byte((i * 7) mod 256)
    var phase = 0
    var gotSmall, gotBig: seq[byte]
    loop.connect("127.0.0.1", 30103,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "POST", "/echo", endStream = false)
        peer.peerBody(1, small)
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        {.gcsafe.}:
          peer.peerFeed(data)
          if phase == 0 and peer.respDone.getOrDefault(1, false):
            gotSmall = peer.respBody.getOrDefault(1, @[])
            phase = 1
            peer.peerHeaders(3, "POST", "/echo", endStream = false)
            peer.peerBody(3, big)
          elif phase == 1 and peer.respDone.getOrDefault(3, false):
            gotBig = peer.respBody.getOrDefault(3, @[])
            conn.close()
            srv.close()
            loop.stop()
      ,
    )
    watchdog(loop, srv)
    loop.run()
    check gotSmall == small
    check gotBig == big
    loop.close()

test "h2_request_oversize_reset":
  # Over maxBody (8 MB default? no — shrink it) the stream is refused.
  let loop = newLoop()
  let srv = newH2Server(loop, streamHandler, maxBody = 4096)
  srv.listen("127.0.0.1", 30104)
  var peer: H2Peer
  var big = newSeq[byte](32_768)
  loop.connect("127.0.0.1", 30104,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodeSettings(newSeq[H2Setting]()))
      peer.peerHeaders(1, "POST", "/echo", endStream = false)
      peer.peerBody(1, big)
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      {.gcsafe.}:
        peer.peerFeed(data)
        if peer.streamReset.getOrDefault(1, false):
          conn.close()
          srv.close()
          loop.stop()
    ,
  )
  watchdog(loop, srv)
  loop.run()
  check peer.streamReset.getOrDefault(1, false)
  loop.close()

# ── C1c: per-stream timeout ──────────────────────────────────────────────────

test "h2_stream_timeout":
  let loop = newLoop()
  let srv = newH2Server(loop, streamHandler, streamTimeoutMs = 200)
  srv.listen("127.0.0.1", 30105)
  var peer: H2Peer
  loop.connect("127.0.0.1", 30105,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodeSettings(newSeq[H2Setting]()))
      # Headers without END_STREAM: the stream idles until the sweep kills it.
      peer.peerHeaders(1, "POST", "/echo", endStream = false)
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      peer.peerFeed(data)
      if peer.streamReset.getOrDefault(1, false):
        conn.close()
        srv.close()
        loop.stop()
    ,
  )
  watchdog(loop, srv)
  loop.run()
  check peer.streamReset.getOrDefault(1, false)
  loop.close()

# ── C2: accessors, sendFile, sendError, extended CONNECT ─────────────────────

test "h2_request_accessors":
  withServer(30106) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    loop.connect("127.0.0.1", 30106,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "GET", "/accessors?q=1", endStream = false,
                         extra = @[("x-test", "yes")])
        peer.peerBody(1, @[byte('h'), byte('i')])
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
    # doAsserts inside the handler would have failed the request with 500.
    check peer.respStatus(1) == "200"
    loop.close()

test "h2_sendfile":
  let path = getTempDir() / "powpow-h2-sendfile.bin"
  var want = newSeq[byte](200_000)
  for i in 0 ..< want.len: want[i] = byte((i * 13) mod 251)
  var f = open(path, fmWrite)
  discard f.writeBuffer(addr want[0], want.len)
  f.close()
  withServer(30107) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    loop.connect("127.0.0.1", 30107,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "GET", "/sendfile",
                         extra = @[("x-file", path)])
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
    check peer.respHeader(1, "content-length") == $want.len
    check peer.respBody.getOrDefault(1, @[]) == want
    loop.close()
  try:
    removeFile(path)
  except OSError:
    discard

test "h2_senderror":
  withServer(30108) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    loop.connect("127.0.0.1", 30108,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "GET", "/error")
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
    check peer.respStatus(1) == "404"
    loop.close()

proc connectHeaders(peer: H2Peer, sid: int32, withProtocol: bool,
                    meth = "CONNECT") =
  ## Raw HEADERS with optional :protocol pseudo-header (RFC 8441).
  var hs = @[HpackHeader(name: ":method", value: meth),
             HpackHeader(name: ":scheme", value: "https"),
             HpackHeader(name: ":path", value: "/connect"),
             HpackHeader(name: ":authority", value: "127.0.0.1")]
  if withProtocol:
    hs.add(HpackHeader(name: ":protocol", value: "websocket"))
  peer.peerSend(encodeHeaders(sid, peer.enc.encode(hs), endStream = true))

test "h2_extended_connect":
  withServer(30109) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    var phase = 0
    var gotProto = ""
    loop.connect("127.0.0.1", 30109,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        # Advertise ENABLE_CONNECT_PROTOCOL like a WS-capable client.
        peer.peerSend(encodeSettings(@[H2Setting(id: 8, value: 1)]))
        # Stream 1: :protocol WITHOUT... (peer setting already sent, so
        # use GET to prove the method gate instead).
        connectHeaders(peer, 1, withProtocol = true, meth = "GET")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        {.gcsafe.}:
          peer.peerFeed(data)
          if phase == 0 and peer.streamReset.getOrDefault(1, false):
            # GET + :protocol rejected; now a legal extended CONNECT.
            phase = 1
            connectHeaders(peer, 3, withProtocol = true)
          elif phase == 1 and peer.respDone.getOrDefault(3, false):
            var b = ""
            for x in peer.respBody.getOrDefault(3, @[]):
              b.add(char(x))
            gotProto = b
            conn.close()
            srv.close()
            loop.stop()
      ,
    )
    watchdog(loop, srv)
    loop.run()
    check gotProto == "proto=websocket meth=CONNECT"
    loop.close()

test "h2_extended_connect_no_peer_setting":
  # Server default enables the gate, but the peer never sent
  # ENABLE_CONNECT_PROTOCOL: :protocol must be refused.
  withServer(30110) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    loop.connect("127.0.0.1", 30110,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        connectHeaders(peer, 1, withProtocol = true)
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        peer.peerFeed(data)
        if peer.streamReset.getOrDefault(1, false):
          conn.close()
          srv.close()
          loop.stop()
      ,
    )
    watchdog(loop, srv)
    loop.run()
    check peer.streamReset.getOrDefault(1, false)
    loop.close()

test "h2_preface_advertises_connect_protocol":
  # The server preface SETTINGS carries ENABLE_CONNECT_PROTOCOL = 1.
  let loop = newLoop()
  let srv = newH2Server(loop, streamHandler)
  srv.listen("127.0.0.1", 30111)
  var sawConnectSetting = false
  var peer: H2Peer
  loop.connect("127.0.0.1", 30111,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.onFrame = proc(p: H2Peer, f: H2Frame) {.closure.} =
        if f.rawType == 4 and (f.flags and H2FlagAck) == 0:
          for st in f.decodeSettings():
            if st.id == 8 and st.value == 1:
              sawConnectSetting = true
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodeSettings(newSeq[H2Setting]()))
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      peer.peerFeed(data)
      if sawConnectSetting:
        conn.close()
        srv.close()
        loop.stop()
    ,
  )
  watchdog(loop, srv)
  loop.run()
  check sawConnectSetting
  loop.close()

# ── C3: autotune + drain ─────────────────────────────────────────────────────

test "h2_autotune_grows_window":
  # A 200 KB upload exhausts the 64 KiB window repeatedly: later
  # WINDOW_UPDATEs must exceed the initial window (autotune growth).
  withServer(30112) do (srv: H2Server, loop: Loop):
    var peer: H2Peer
    var maxInc = 0
    var big = newSeq[byte](200_000)
    for i in 0 ..< big.len: big[i] = byte(i mod 251)
    loop.connect("127.0.0.1", 30112,
      onConnect = proc(conn: Connection) =
        peer = newPeer(conn)
        peer.onFrame = proc(p: H2Peer, f: H2Frame) {.closure.} =
          if f.rawType == 8 and f.streamId == 1:
            let inc = int(f.decodeWindowUpdate())
            if inc > maxInc:
              maxInc = inc
        peer.peerSendStr(H2Magic)
        peer.peerSend(encodeSettings(newSeq[H2Setting]()))
        peer.peerHeaders(1, "POST", "/echo", endStream = false)
        peer.peerBody(1, big)
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
    check peer.respBody.getOrDefault(1, @[]) == big
    check maxInc > 65535
    loop.close()

test "h2_graceful_drain":
  let loop = newLoop()
  var held: H2Response
  let srv = newH2Server(loop, proc(req: H2Request,
                                   res: H2Response) {.gcsafe, closure.} =
    {.gcsafe.}:
      if req.path == "/slow":
        held = res
        res.sendHeaders()
      else:
        res.status(200).send("fresh")
  )
  srv.listen("127.0.0.1", 30113)
  var peer: H2Peer
  var drained = false
  var listenAlive = true
  loop.connect("127.0.0.1", 30113,
    onConnect = proc(conn: Connection) =
      peer = newPeer(conn)
      peer.peerSendStr(H2Magic)
      peer.peerSend(encodeSettings(newSeq[H2Setting]()))
      peer.peerHeaders(1, "GET", "/slow", endStream = true)
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      {.gcsafe.}:
        peer.peerFeed(data)
        if peer.respDone.getOrDefault(1, false):
          # Client side done; the drain checker still needs polls to fire
          # `drained`, so only the watchdog or `drained` stops the loop.
          conn.close()
    ,
  )
  # Drain while stream 1 is open: GOAWAY goes out, the stream lives.
  # Do NOT stop the loop here: teardown writes flush on later polls.
  discard loop.addTimer(100) do (id: int):
    srv.drain(2000, proc() {.closure, gcsafe.} =
      {.gcsafe.}:
        drained = true
        listenAlive = srv.tcp.fd.int >= 0
        srv.close()
        loop.stop()
    )
  # A post-GOAWAY stream must be refused, not processed.
  discard loop.addTimer(150) do (id: int):
    peer.peerHeaders(5, "GET", "/fresh", endStream = true)
  # Finish the in-flight stream after the drain.
  discard loop.addTimer(250) do (id: int):
    if held != nil:
      held.sendChunk("late")
      held.finish()
  watchdog(loop, srv)
  loop.run()
  check peer.gotGoaway
  check peer.streamReset.getOrDefault(5, false)
  var body = ""
  for b in peer.respBody.getOrDefault(1, @[]):
    body.add(char(b))
  check body == "late"
  check drained
  check not listenAlive
  loop.close()
