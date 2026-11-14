## tests/test_ws_deflate.nim — WebSocket permessage-deflate (Phase 1D).
##
## RFC 7692, no-context-takeover only, both directions: unit roundtrips,
## offer parsing, live echo in both roles, fragmented compressed messages,
## raw-wire RSV1 checks, decompression-bomb rejection, server ping
## interval, and the pendingBytes backpressure accessor.

import std/httpcore except HttpMethod
import std/unittest
import std/[base64, strutils, os]
import ../src/powpow
import ../src/powpow/proto/ws

const DeflateOfferHdr =
  "permessage-deflate; client_no_context_takeover; server_no_context_takeover"

# ── Unit: codec roundtrips ───────────────────────────────────────────────────

test "deflate_roundtrip_text_and_binary":
  let texts = ["hello", "a", "x".repeat(10_000),
               "the quick brown fox jumps over the lazy dog ".repeat(500)]
  for t in texts:
    check wsInflate(wsDeflate(t), 100_000_000) == t
  var bin = newSeq[byte](50_000)
  for i in 0 ..< bin.len:
    bin[i] = byte((i * 7) mod 256)
  let dec = wsInflate(wsDeflate(bin), 100_000_000)
  check dec.len == bin.len
  for i in 0 ..< bin.len:
    check dec[i] == char(bin[i])

test "deflate_empty_message":
  # An empty message still encodes as a (tiny) valid block.
  let c = wsDeflate("")
  check c.len > 0
  check wsInflate(c, 1024) == ""

test "deflate_cap_and_corrupt":
  let c = wsDeflate("hello world, hello world")
  var tooLarge = false
  try:
    discard wsInflate(c, 2)
  except WsDeflateTooLarge:
    tooLarge = true
  check tooLarge
  var corrupt = false
  try:
    discard wsInflate("not valid deflate bytes at all...........", 1_000_000)
  except WsDeflateError:
    corrupt = true
  check corrupt
  var emptyBad = false
  try:
    discard wsInflate([], 1024)
  except WsDeflateError:
    emptyBad = true
  check emptyBad

test "deflate_offer_parsing":
  check parseDeflateOffer(DeflateOfferHdr)
  check parseDeflateOffer("PerMessage-Deflate; Client_No_Context_Takeover; " &
    "Server_No_Context_Takeover")
  check parseDeflateOffer("gzip, permessage-deflate; " &
    "server_no_context_takeover; client_no_context_takeover")
  # Missing one side: refused.
  check not parseDeflateOffer("permessage-deflate; client_no_context_takeover")
  check not parseDeflateOffer("permessage-deflate; server_no_context_takeover")
  check not parseDeflateOffer("permessage-deflate")
  # Window-bits tuning: refused (we only do stateless one-shots).
  check not parseDeflateOffer(DeflateOfferHdr & "; client_max_window_bits=12")
  check not parseDeflateOffer("permessage-deflate; server_max_window_bits=15; " &
    "client_no_context_takeover; server_no_context_takeover")
  # Unrelated extensions ignored.
  check not parseDeflateOffer("x-custom; foo=1")
  check not parseDeflateOffer("")

test "deflate_transmitted_bit_is_nonfinal":
  # The transmitted payload is a non-final block: the receiver's suffix
  # completes it. First byte LSB (BFINAL) must be 0 after wsDeflate.
  let c = wsDeflate("hello")
  check (c[0].ord and 0x01) == 0

test "pending_bytes_nil_is_zero":
  check pendingBytes(Connection(nil)) == 0
  check pendingBytes(WsConnection(nil)) == 0

# ── Live helpers ─────────────────────────────────────────────────────────────

proc silentWsServer(port: int, permessageDeflate = false,
                    pingIntervalMs = 0,
                    maxFrameSize = DefaultMaxFrameSize): tuple[srv: WsServer,
    loop: Loop] =
  let loop = newLoop()
  let srv = newWsServer(loop, maxFrameSize, pingIntervalMs, permessageDeflate)
  srv.onMessage do (ws: WsConnection, kind: WsFrameKind,
                    data: openArray[byte]):
    # Echo preserving kind (compressed on the way back when negotiated).
    if kind == wsText:
      ws.sendText(cast[string](@data))
    else:
      ws.sendBinary(data)
  result = (srv, loop)
  srv.listen("127.0.0.1", port)

# ── Live: both roles echo with deflate ───────────────────────────────────────

test "deflate_live_standalone_both_roles":
  let (srv, loop) = silentWsServer(19960, permessageDeflate = true)
  var gotText = ""
  var gotBin = newSeq[byte]()
  var opened = false
  var negotiated = false
  discard loop.addTimer(10) do (id: int):
    let ws = connectWs(loop, "127.0.0.1", 19960, "/",
      permessageDeflate = true,
      onOpen = proc(ws: WsConnection) =
        opened = true
        negotiated = ws.permessageDeflate
        ws.sendText("hello deflate")
        var bin = newSeq[byte](20_000)
        for i in 0 ..< bin.len:
          bin[i] = byte(i mod 251)
        ws.sendBinary(bin)
      ,
      onMessage = proc(ws: WsConnection, kind: WsFrameKind,
                       data: openArray[byte]) =
        if kind == wsText:
          gotText = cast[string](@data)
        else:
          gotBin = @data
        if gotText.len > 0 and gotBin.len > 0:
          ws.closeWs(1000, "done")
          srv.close()
          loop.stop()
      ,
      onError = proc(ws: WsConnection, err: string) =
        loop.stop()
    )
    check ws != nil
  discard loop.addTimer(15_000) do (id: int):
    srv.close()
    loop.stop()
  loop.run()
  loop.close()
  check opened
  check negotiated
  check gotText == "hello deflate"
  check gotBin.len == 20_000
  for i in 0 ..< gotBin.len:
    check gotBin[i] == byte(i mod 251)

test "deflate_live_upgrade_path":
  # HttpServer route upgrade with permessageDeflate enabled.
  let loop = newLoop()
  let httpSrv = newHttpServer(loop)
  httpSrv.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.cast(gcsafe).}:
      if req.getPath() == "/ws":
        discard websocketUpgrade(res, req, httpSrv, permessageDeflate = true,
          onMessage = proc(ws: WsConnection, kind: WsFrameKind,
                           data: openArray[byte]) =
            ws.sendText("up:" & cast[string](@data))
        )
      else:
        res.status(Http404).send("nope")
  httpSrv.listen("127.0.0.1", 19961)
  var got = ""
  var negotiated = false
  discard loop.addTimer(10) do (id: int):
    let ws = connectWs(loop, "127.0.0.1", 19961, "/ws",
      permessageDeflate = true,
      onOpen = proc(ws: WsConnection) =
        negotiated = ws.permessageDeflate
        ws.sendText("ping-upgrade")
      ,
      onMessage = proc(ws: WsConnection, kind: WsFrameKind,
                       data: openArray[byte]) =
        got = cast[string](@data)
        ws.closeWs(1000, "done")
        httpSrv.close()
        loop.stop()
      ,
      onError = proc(ws: WsConnection, err: string) =
        loop.stop()
    )
    check ws != nil
  discard loop.addTimer(15_000) do (id: int):
    httpSrv.close()
    loop.stop()
  loop.run()
  loop.close()
  check negotiated
  check got == "up:ping-upgrade"

# ── Live: interop when one side declines ─────────────────────────────────────

test "deflate_plain_server_ignores_offer":
  # Deflate client vs plain server: handshake succeeds, session stays
  # uncompressed.
  let (srv, loop) = silentWsServer(19962)
  var got = ""
  var negotiated = true
  discard loop.addTimer(10) do (id: int):
    let ws = connectWs(loop, "127.0.0.1", 19962, "/",
      permessageDeflate = true,
      onOpen = proc(ws: WsConnection) =
        negotiated = ws.permessageDeflate
        ws.sendText("plain please")
      ,
      onMessage = proc(ws: WsConnection, kind: WsFrameKind,
                       data: openArray[byte]) =
        got = cast[string](@data)
        ws.closeWs(1000, "done")
        srv.close()
        loop.stop()
      ,
      onError = proc(ws: WsConnection, err: string) =
        loop.stop()
    )
    check ws != nil
  discard loop.addTimer(15_000) do (id: int):
    srv.close()
    loop.stop()
  loop.run()
  loop.close()
  check not negotiated
  check got == "plain please"

test "deflate_plain_client_no_compression":
  # Plain client vs deflate server: server must not compress (client never
  # offered), echo still round-trips.
  let (srv, loop) = silentWsServer(19963, permessageDeflate = true)
  var got = ""
  var opened = false
  discard loop.addTimer(10) do (id: int):
    let ws = connectWs(loop, "127.0.0.1", 19963, "/",
      onOpen = proc(ws: WsConnection) =
        opened = true
        ws.sendText("no deflate here")
      ,
      onMessage = proc(ws: WsConnection, kind: WsFrameKind,
                       data: openArray[byte]) =
        got = cast[string](@data)
        ws.closeWs(1000, "done")
        srv.close()
        loop.stop()
      ,
      onError = proc(ws: WsConnection, err: string) =
        loop.stop()
    )
    check ws != nil
  discard loop.addTimer(15_000) do (id: int):
    srv.close()
    loop.stop()
  loop.run()
  loop.close()
  check opened
  check got == "no deflate here"

# ── Raw-wire tests ───────────────────────────────────────────────────────────

proc wsRawConnect(loop: Loop, port: int, extOffer = ""): Connection =
  ## Blocking-style raw TCP connect on the loop: handshake bytes are written
  ## synchronously (loopback), the response is pumped via a temp watcher.
  var conn: Connection
  var done = false
  var key = ""
  var rng = 7
  var kb: array[16, byte]
  for i in 0 ..< 16:
    rng = (rng * 1103515245 + 12345) and 0x7FFFFFFF
    kb[i] = byte(rng mod 256)
  key = base64.encode(kb)
  loop.connect("127.0.0.1", port,
    onConnect = proc(c: Connection) =
      conn = c
      var req = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n" &
        "Upgrade: websocket\r\nConnection: Upgrade\r\n" &
        "Sec-WebSocket-Key: " & key & "\r\n" &
        "Sec-WebSocket-Version: 13\r\n"
      if extOffer.len > 0:
        req.add("Sec-WebSocket-Extensions: " & extOffer & "\r\n")
      req.add("\r\n")
      discard conn.send(req)
      done = true
      loop.stop()
    ,
    onData = proc(c: Connection, data: openArray[byte]) = discard
  )
  loop.run()
  doAssert done and conn != nil
  conn

proc wsRawRead(conn: Connection, loop: Loop, ms = 5000): seq[byte] =
  ## Read available bytes (single pump): registers a one-shot watcher.
  var box = new(seq[byte])
  box[] = @[]
  let fd = conn.fd.int
  loop.register(fd, {Read}, edgeTriggered = false,
    callback = proc(efd: int, ev: set[EventType]) =
      if Read in ev:
        var buf: array[65536, byte]
        let n = sockRecv(conn.fd, addr buf[0], buf.len)
        if n > 0:
          box[].add(buf.toOpenArray(0, n - 1))
  )
  discard loop.addTimer(ms) do (id: int):
    loop.stop()
  loop.run()
  loop.unregister(fd)
  box[]

proc wsRawFrame(opcode: int, fin: bool, rsv1: bool,
                payload: openArray[byte]): seq[byte] =
  ## Build a masked client frame.
  var mask = [0x12'u8, 0x34, 0x56, 0x78]
  result = @[]
  var b0 = byte(opcode and 0x0F)
  if fin: b0 = b0 or 0x80
  if rsv1: b0 = b0 or 0x40
  result.add(b0)
  let n = payload.len
  if n < 126:
    result.add(byte(0x80 or n))
  elif n <= 0xFFFF:
    result.add(byte(0x80 or 126))
    result.add(byte((n shr 8) and 0xFF))
    result.add(byte(n and 0xFF))
  else:
    result.add(byte(0x80 or 127))
    for i in countdown(7, 0):
      result.add(byte((uint64(n) shr (i * 8)) and 0xFF))
  for m in mask: result.add(m)
  for i in 0 ..< n:
    result.add(payload[i] xor mask[i mod 4])

test "deflate_server_refuses_context_takeover":
  # Offer without no-context-takeover: handshake succeeds but no extension
  # is negotiated (session stays uncompressed).
  let loop = newLoop()
  let srv = newWsServer(loop, permessageDeflate = true)
  var got = ""
  srv.onMessage do (ws: WsConnection, kind: WsFrameKind,
                    data: openArray[byte]):
    got = cast[string](@data)
    ws.sendText("echo:" & got)
    check not ws.permessageDeflate
  srv.listen("127.0.0.1", 19964)
  var resp = ""
  var conn: Connection
  discard loop.addTimer(10) do (id: int):
    conn = wsRawConnect(loop, 19964, "permessage-deflate")
    var buf = wsRawRead(conn, loop, 3000)
    resp = cast[string](buf)
    loop.stop()
  loop.run()
  check resp.contains("101")
  check not resp.toLowerAscii().contains("sec-websocket-extensions")
  # Session works uncompressed: masked text frame, expect plain echo.
  let fr = wsRawFrame(0x1, true, false, "hi".toOpenArrayByte(0, 1))
  discard conn.send(fr)
  let echoBytes = wsRawRead(conn, loop, 3000)
  # Server frame: FIN+text, no RSV1, 6-byte payload "echo:hi".
  check echoBytes.len >= 2
  check (echoBytes[0] and 0x40) == 0  # RSV1 clear
  check (echoBytes[0] and 0x0F) == 0x01
  check echoBytes[1] == 7
  var body = ""
  for i in 0 ..< 7:
    body.add(char(echoBytes[2 + i]))
  check body == "echo:hi"
  conn.close()
  srv.close()
  loop.close()

test "deflate_wire_rsv1_and_fragmented":
  # Raw peer: handshake with deflate, send fragmented compressed message,
  # verify the echo arrives compressed (RSV1) and decompresses.
  let loop = newLoop()
  let srv = newWsServer(loop, permessageDeflate = true)
  srv.onMessage do (ws: WsConnection, kind: WsFrameKind,
                    data: openArray[byte]):
    check ws.permessageDeflate
    ws.sendBinary(data)
  srv.listen("127.0.0.1", 19965)
  var resp = ""
  var conn: Connection
  discard loop.addTimer(10) do (id: int):
    conn = wsRawConnect(loop, 19965, DeflateOfferHdr)
    var buf = wsRawRead(conn, loop, 3000)
    resp = cast[string](buf)
    loop.stop()
  loop.run()
  check resp.contains("101")
  check resp.toLowerAscii().contains("permessage-deflate")
  let msg = "fragmented deflate payload, repeated: ".repeat(200)
  let comp = wsDeflate(msg)
  check comp.len > 4
  let half = comp.len div 2
  # First fragment: FIN=0, RSV1=1, binary.
  discard conn.send(wsRawFrame(0x2, false, true,
    comp.toOpenArrayByte(0, half - 1)))
  # Continuation: FIN=1, RSV1=0.
  discard conn.send(wsRawFrame(0x0, true, false,
    comp.toOpenArrayByte(half, comp.high)))
  let echoBytes = wsRawRead(conn, loop, 5000)
  check echoBytes.len > 2
  check (echoBytes[0] and 0x40) != 0  # echo is compressed: RSV1 set
  check (echoBytes[0] and 0x0F) == 0x02
  # Unframe (server frames are unmasked, small extended length possible).
  var pos = 1
  let b1 = echoBytes[pos]; inc pos
  var payLen = int(b1 and 0x7F)
  if payLen == 126:
    payLen = (int(echoBytes[pos]) shl 8) or int(echoBytes[pos + 1])
    pos += 2
  elif payLen == 127:
    payLen = 0
    for i in 0 ..< 8:
      payLen = (payLen shl 8) or int(echoBytes[pos + i])
    pos += 8
  let payload = echoBytes[pos ..< pos + payLen]
  check wsInflate(payload, 1_000_000) == msg
  conn.close()
  srv.close()
  loop.close()

test "deflate_bomb_rejected_with_1009":
  # 1 MB of zeros compresses to ~1 KB: over a 64 KB cap it must die with
  # 1009, not with an OOM.
  let loop = newLoop()
  let srv = newWsServer(loop, 65536, 0, true)
  srv.onMessage do (ws: WsConnection, kind: WsFrameKind,
                    data: openArray[byte]):
    ws.sendBinary(data)  # must never run for the bomb
  srv.listen("127.0.0.1", 19966)
  discard loop.addTimer(10) do (id: int):
    let conn = wsRawConnect(loop, 19966, DeflateOfferHdr)
    let hs = wsRawRead(conn, loop, 3000)
    check cast[string](hs).contains("101")
    let zeros = newString(1_000_000)
    let comp = wsDeflate(zeros)
    check comp.len < 65536  # passes the frame cap: the bomb is the ratio
    discard conn.send(wsRawFrame(0x2, true, true,
      comp.toOpenArrayByte(0, comp.high)))
    let resp = wsRawRead(conn, loop, 5000)
    # Close frame with code 1009.
    check resp.len >= 4
    check (resp[0] and 0x0F) == 0x08
    let code = (int(resp[2]) shl 8) or int(resp[3])
    check code == 1009
    conn.close()
    srv.close()
    loop.stop()
  discard loop.addTimer(15_000) do (id: int):
    srv.close()
    loop.stop()
  loop.run()
  loop.close()

test "deflate_server_ping_interval":
  # Raw peer (never speaks after the handshake) observes server pings.
  # Single outer run (no nested loop.run): the connect handshake and the
  # ping wait all pump on it.
  let loop = newLoop()
  let srv = newWsServer(loop, 10 * 1024 * 1024, 100, false)
  srv.listen("127.0.0.1", 19967)
  var sawPing = false
  discard loop.addTimer(10) do (id: int):
    loop.connect("127.0.0.1", 19967,
      onConnect = proc(conn: Connection) =
        discard conn.send("GET / HTTP/1.1\r\nHost: x\r\n" &
          "Upgrade: websocket\r\nConnection: Upgrade\r\n" &
          "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" &
          "Sec-WebSocket-Version: 13\r\n\r\n")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        # Ping = FIN + opcode 9. The 101 bytes never match (all ASCII).
        for b in data:
          if (b and 0x0F) == 0x09 and (b and 0x80) != 0:
            sawPing = true
            conn.close()
            srv.close()
            loop.stop()
            break
    )
  discard loop.addTimer(5000) do (id: int):
    srv.close()
    loop.stop()
  loop.run()
  loop.close()
  check sawPing

test "deflate_pending_bytes_drains":
  # Backpressure counter: idle is zero; it exists and drains after echo.
  let loop = newLoop()
  let srv = newWsServer(loop)
  var wsRef: WsConnection
  srv.onOpen do (ws: WsConnection):
    wsRef = ws
  srv.onMessage do (ws: WsConnection, kind: WsFrameKind,
                    data: openArray[byte]):
    check ws.pendingBytes() >= 0
    ws.sendBinary(data)
  srv.listen("127.0.0.1", 19968)
  check pendingBytes(WsConnection(nil)) == 0
  discard loop.addTimer(10) do (id: int):
    let ws = connectWs(loop, "127.0.0.1", 19968, "/",
      onOpen = proc(ws: WsConnection) =
        check ws.pendingBytes() == 0
        ws.sendBinary([1.byte, 2, 3])
      ,
      onMessage = proc(ws: WsConnection, kind: WsFrameKind,
                       data: openArray[byte]) =
        ws.closeWs(1000, "done")
        srv.close()
        loop.stop()
      ,
      onError = proc(ws: WsConnection, err: string) =
        loop.stop()
    )
    check ws != nil
  discard loop.addTimer(15_000) do (id: int):
    srv.close()
    loop.stop()
  loop.run()
  check wsRef != nil
  check wsRef.pendingBytes() == 0
  srv.close()
  loop.close()
