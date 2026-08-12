# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## RFC 6455 WebSocket server.
##
## Two modes of operation:
##
## 1. Standalone — dedicated WebSocket server on its own TCP port:
##
##   ```nim
##   let loop = newLoop()
##   let wss = newWsServer(loop)
##   wss.onOpen do (ws: WsConnection):
##     echo "client connected"
##   wss.onMessage do (ws: WsConnection, kind: WsFrameKind, data: openArray[byte]):
##     ws.sendText("echo: " & cast[string](@data))
##   wss.listen("0.0.0.0", 9001)
##   loop.run()
##   ```
##
## 2. Upgraded from HttpServer — route handler performs the handshake:
##
##   ```nim
##   server.get("/ws") do (req: HttpRequest, res: Response):
##     websocketUpgrade(res, req, onOpen, onMessage, onClose)
##   ```

import std/[httpcore, base64, tables, strutils]
import pkg/checksums/sha1
when defined(threads):
  import std/threads

import ../net/tcp
import ../net/common
import ../loop
import ../types
import ../proto/http
import ../proto/httpserver

# ── Constants ────────────────────────────────────────────────────────────────

const
  wsGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  MaxControlPayload = 125       ## Max payload for control frames (RFC 6455 §5.5)
  DefaultWsBufSize  = 65536    ## Initial frame parser buffer
  DefaultMaxFrameSize* = 10 * 1024 * 1024  ## Default max WebSocket frame size (10 MB)
  WsHardMaxFrameSize = 512 * 1024 * 1024  ## Absolute allocation cap: applied even
    ## when maxFrameSize == 0, so a hostile 64-bit frame length can never drive an
    ## unbounded newSeq (OOM / negative-length allocation) or an unbounded
    ## fragmented-message assembly.

# ── Types ────────────────────────────────────────────────────────────────────

type
  WsFrameKind* = enum
    ## WebSocket frame opcodes.
    wsContinuation = 0x0
    wsText         = 0x1
    wsBinary       = 0x2
    wsClose        = 0x8
    wsPing         = 0x9
    wsPong         = 0xA

  WsConnection* = ref object of RootObj
    ## A WebSocket connection. Wraps a TCP connection with frame
    ## parsing, fragmentation reassembly, and control frame handling.
    conn*:       Connection       ## Underlying TCP connection
    parser:      WsFrameParser    ## Incremental frame parser
    onMessage*:  WsMessageCb
    onClose*:    WsCloseCb
    onError*:    WsErrorCb
    onOpen*:     WsOpenCb
    maxFrameSize*: int
    # Fragmentation reassembly
    assembling:  bool
    fragOpcode:  int
    assembleBuf: seq[byte]
    # Post-upgrade idle/read timeout (0 = disabled). Bumped on every parsed
    # frame; a sweep/one-shot timer closes the connection if no frame arrives
    # within `idleTimeoutMs` — an upgraded but silent client must not hold the
    # connection + fd forever.
    lastActive: int64
    idleTimer:  TimerId
    idleTimeoutMs: int

  WsMessageCb* = proc(ws: WsConnection, kind: WsFrameKind,
                       data: openArray[byte]) {.closure.}
  WsCloseCb*   = proc(ws: WsConnection, code: int,
                       reason: string) {.closure.}
  WsErrorCb*   = proc(ws: WsConnection, err: string) {.closure.}
  WsOpenCb*    = proc(ws: WsConnection) {.closure.}

  # Frame parser state machine
  WsParsePhase = enum
    WsPhaseHeader       ## Reading the 2-byte frame header
    WsPhaseLength16     ## Reading 16-bit extended length
    WsPhaseLength64     ## Reading 64-bit extended length
    WsPhaseMask         ## Reading 4-byte mask key
    WsPhasePayload      ## Reading payload bytes
    WsPhaseReady        ## Complete frame available

  WsFrameParser = ref object
    phase:       WsParsePhase
    # Parsed fields from the current frame
    fin:         bool
    opcode:      int
    masked:      bool
    payloadLen:  uint64
    maskKey:     array[4, uint8]
    maskIdx:     int            # bytes read so far for mask key
    lengthBuf:   array[8, uint8]
    lengthIdx:   int            # bytes read so far for extended length
    # Payload accumulation
    payload:     seq[byte]
    payloadOff:  int            # bytes consumed so far

  WsServer* = ref object
    ## Standalone WebSocket server.
    tcpServer: TcpServer
    loop:      Loop
    conns:     Table[int, WsConnection]  ## fd → connection
    wsPool:    seq[WsConnection]         ## idle connections recycled across upgrades
    maxFrameSize*: int
    handshakeSessions: Table[int, HttpParser]  ## fd → pre-upgrade HTTP parser
    handshakeTimers:   Table[int, TimerId]     ## fd → handshake timeout timer
    handshakeTimeoutMs*: int
      ## Close connections that never complete the HTTP→WebSocket handshake
      ## within this many ms (0 = disabled). Prevents handshake-stall DoS.
    idleTimeoutMs*: int
      ## Close upgraded connections that send no frames within this many ms
      ## (0 = disabled). Prevents post-upgrade idle connections from holding a
      ## connection + fd forever.
    maxHandshakeSessions*: int
      ## Hard cap on in-flight handshake sessions (0 = unlimited).
    # User callbacks (applied to all connections)
    defaultOpen:    WsOpenCb
    defaultMessage: WsMessageCb
    defaultClose:   WsCloseCb
    defaultError:   WsErrorCb

# ── Frame parser ─────────────────────────────────────────────────────────────

proc newWsFrameParser(): WsFrameParser {.inline.} =
  WsFrameParser(
    phase: WsPhaseHeader,
    payload: newSeq[byte](DefaultWsBufSize),
  )

proc reset*(p: WsFrameParser) =
  ## Reset the parser for the next frame.
  p.phase = WsPhaseHeader
  p.fin = false
  p.opcode = 0
  p.masked = false
  p.payloadLen = 0
  p.maskIdx = 0
  p.lengthIdx = 0
  p.payloadOff = 0

# ── WS handshake helpers ─────────────────────────────────────────────────────

func computeAcceptKey*(clientKey: string): string =
  ## Compute the Sec-WebSocket-Accept value from the client's key.
  let digest = sha1.secureHash(clientKey & wsGuid)
  let shaArray = cast[array[0..19, uint8]](digest)
  result = base64.encode(shaArray)

proc buildHandshakeResponse*(acceptKey: string): string =
  ## Build the HTTP 101 Switching Protocols response for a WebSocket upgrade.
  result = "HTTP/1.1 101 Switching Protocols\r\n" &
           "Upgrade: websocket\r\n" &
           "Connection: Upgrade\r\n" &
           "Sec-WebSocket-Accept: " & acceptKey & "\r\n" &
           "\r\n"

proc sendHandshake*(conn: Connection, clientKey: string) {.inline.} =
  let response = buildHandshakeResponse(computeAcceptKey(clientKey))
  discard conn.send(response)

# ── Frame writer ─────────────────────────────────────────────────────────────

proc writeFrame*(conn: Connection, opcode: int, payload: openArray[byte]) =
  ## Write a single WebSocket frame to the connection.
  ## Server frames are never masked (RFC 6455 §5.1).
  if conn.state != Connected: return

  var header: array[10, uint8]
  var hlen = 2

  header[0] = uint8(0x80 or (opcode and 0x0F))  # FIN=1 + opcode

  let n = payload.len
  if n < 126:
    header[1] = uint8(n)
    hlen = 2
  elif n <= 0xFFFF:
    header[1] = 126
    header[2] = uint8((n shr 8) and 0xFF)
    header[3] = uint8(n and 0xFF)
    hlen = 4
  else:
    header[1] = 127
    var v = uint64(n)
    for i in 0 ..< 8:
      header[9 - i] = uint8(v and 0xFF)
      v = v shr 8
    hlen = 10

  let hdrPtr = cast[ptr UncheckedArray[byte]](addr header[0])
  if n > 0:
    discard conn.sendv([(hdrPtr, hlen), (cast[ptr UncheckedArray[byte]](unsafeAddr payload[0]), n)])
  else:
    discard conn.send(header.toOpenArray(0, hlen - 1))

proc writeFrameMasked*(conn: Connection, opcode: int, payload: openArray[byte],
                       mask: array[4, uint8]) =
  ## Write a masked WebSocket frame (for client-to-server; servers don't mask).
  var header: array[14, uint8]  # max header: 2 + 8 + 4
  var hlen = 2

  header[0] = uint8(0x80 or (opcode and 0x0F))
  header[1] = 0x80  # mask bit

  let n = payload.len
  if n < 126:
    header[1] = header[1] or uint8(n)
    hlen = 2
  elif n <= 0xFFFF:
    header[1] = header[1] or 126
    header[2] = uint8((n shr 8) and 0xFF)
    header[3] = uint8(n and 0xFF)
    hlen = 4
  else:
    header[1] = header[1] or 127
    var v = uint64(n)
    for i in 0 ..< 8:
      header[9 - i] = uint8(v and 0xFF)
      v = v shr 8
    hlen = 10

  for i in 0 ..< 4:
    header[hlen + i] = mask[i]
  hlen += 4

  discard conn.send(header.toOpenArray(0, hlen - 1))
  if n > 0:
    # Mask and send payload
    var masked = newSeq[byte](n)
    for i in 0 ..< n:
      masked[i] = uint8(payload[i]) xor mask[i mod 4]
    discard conn.send(masked)

# ── WsConnection send helpers ────────────────────────────────────────────────

proc sendSafe(ws: WsConnection, opcode: int, data: openArray[byte]) =
  ## Thread-safe frame write. When called from a thread other than the loop's
  ## (e.g. a background file-watcher thread notifying clients), the write is
  ## deferred to the loop thread via `postToLoop` so the connection's buffers,
  ## the fd watcher and `ws.conn` are only ever touched on the loop thread.
  ## The deferred closure re-checks that the ws still owns the same connection
  ## and that it is still open, so a recycled/closed ws is never written to.
  let conn = ws.conn
  if conn == nil or conn.state != Connected:
    return
  when defined(threads):
    if conn.loop.ownerThread != cast[int](getThreadId()):
      let payload = @data
      let loop = conn.loop
      loop.postToLoop(proc() =
        if ws.conn == conn and conn.state == Connected:
          conn.writeFrame(opcode, payload))
      return
  conn.writeFrame(opcode, data)

proc sendText*(ws: WsConnection, s: string) {.inline.} =
  if s.len == 0:
    ws.sendSafe(0x1, [])
  else:
    ws.sendSafe(0x1, s.toOpenArrayByte(0, s.high))

proc sendBinary*(ws: WsConnection, data: openArray[byte]) {.inline.} =
  if data.len == 0:
    ws.sendSafe(0x2, [])
  else:
    ws.sendSafe(0x2, data)

proc sendPing*(ws: WsConnection, data: openArray[byte] = []) {.inline.} =
  if data.len == 0:
    ws.sendSafe(0x9, [])
  else:
    ws.sendSafe(0x9, data)

proc sendPong*(ws: WsConnection, data: openArray[byte] = []) {.inline.} =
  if data.len == 0:
    ws.sendSafe(0xA, [])
  else:
    ws.sendSafe(0xA, data)

proc closeWs*(ws: WsConnection, code: int = 1000, reason: string = "") =
  ## Send a close frame and shut down the connection.
  if ws.idleTimer != TimerId(0):
    ws.conn.loop.cancelTimer(ws.idleTimer)
    ws.idleTimer = TimerId(0)
  var payload: seq[byte] = @[]
  if code != 0:
    payload.setLen(2 + reason.len)
    payload[0] = uint8((code shr 8) and 0xFF)
    payload[1] = uint8(code and 0xFF)
    for i, ch in reason:
      payload[2 + i] = uint8(ch.ord and 0xFF)
  ws.conn.writeFrame(0x8, payload)
  ws.conn.close()

# ── Frame parser (incremental, state-machine) ────────────────────────────────

template dispatchFrame(ws: WsConnection; p: WsFrameParser) =
  let opcode = p.opcode
  let plen = int(p.payloadLen)
  p.phase = WsPhaseHeader
  case opcode
  of 0x0:
    if not ws.assembling:
      if not ws.onError.isNil:
        ws.onError(ws, "Unexpected continuation frame")
      ws.closeWs(1002, "Protocol error")
      return
    if ws.maxFrameSize > 0 and (ws.assembleBuf.len + plen) > ws.maxFrameSize:
      ws.closeWs(1009, "Message too large")
      return
    if ws.maxFrameSize == 0 and (ws.assembleBuf.len + plen) > WsHardMaxFrameSize:
      ws.closeWs(1009, "Message too large")
      return
    if plen > 0:
      ws.assembleBuf.add p.payload.toOpenArray(0, plen - 1)
    if p.fin:
      let finalOp = ws.fragOpcode
      ws.assembling = false
      if not ws.onMessage.isNil:
        ws.onMessage(ws, cast[WsFrameKind](finalOp), ws.assembleBuf)
      ws.assembleBuf.setLen(0)
  of 0x1, 0x2:
    if ws.assembling:
      ws.closeWs(1002, "Unexpected data frame during fragmentation")
      return
    if not p.fin and ws.maxFrameSize > 0 and plen > ws.maxFrameSize:
      ws.closeWs(1009, "Message too large")
      return
    if not p.fin and ws.maxFrameSize == 0 and plen > WsHardMaxFrameSize:
      ws.closeWs(1009, "Message too large")
      return
    if p.fin:
      if not ws.onMessage.isNil:
        if plen > 0:
          ws.onMessage(ws, cast[WsFrameKind](opcode), p.payload.toOpenArray(0, plen - 1))
        else:
          ws.onMessage(ws, cast[WsFrameKind](opcode), [])
    else:
      ws.assembling = true
      ws.fragOpcode = opcode
      ws.assembleBuf.setLen(0)
      if plen > 0:
        ws.assembleBuf.add p.payload.toOpenArray(0, plen - 1)
  of 0x8:
    if plen == 1:
      ws.closeWs(1002, "Invalid close payload length")
      return
    var closeCode = 1000
    var reason = ""
    if plen >= 2:
      closeCode = (int(p.payload[0]) shl 8) or int(p.payload[1])
      if closeCode != 1000 and closeCode != 1001 and
         closeCode != 1002 and closeCode != 1003 and
         closeCode != 1007 and closeCode != 1008 and
         closeCode != 1009 and closeCode != 1010 and
         closeCode != 1011 and
         not (closeCode in 3000..4999):
        ws.closeWs(1002, "Invalid close code")
        return
    if plen > 2:
      reason = newString(plen - 2)
      copyMem(addr reason[0], unsafeAddr p.payload[2], plen - 2)
    if plen > 0:
      ws.conn.writeFrame(0x8, p.payload.toOpenArray(0, plen - 1))
    else:
      ws.conn.writeFrame(0x8, [])
    if not ws.onClose.isNil:
      ws.onClose(ws, closeCode, reason)
    ws.conn.close()
    return
  of 0x9:
    if plen > 0:
      ws.conn.writeFrame(0xA, p.payload.toOpenArray(0, plen - 1))
    else:
      ws.conn.writeFrame(0xA, [])
  of 0xA:
    discard
  else:
    if not ws.onError.isNil:
      ws.onError(ws, "Unsupported opcode: " & $opcode)
    ws.closeWs(1003, "Unsupported opcode")
    return

proc parseWsFrames*(ws: WsConnection, data: openArray[byte]) =
  ## Feed incoming TCP data into the WebSocket frame parser.
  ## Dispatches complete frames to the appropriate callbacks.
  ws.lastActive = monoMs()
  var i = 0
  let dataLen = data.len

  let frameLimit = if ws.maxFrameSize > 0: uint64(ws.maxFrameSize)
                   else: uint64(WsHardMaxFrameSize)

  template readByte(): uint8 =
    if i >= dataLen: return
    let b = data[i]
    inc i
    b

  while i < dataLen:
    let p = ws.parser

    case p.phase
    of WsPhaseHeader:
      if dataLen - i < 2:
        # Need at least 2 bytes for the header; wait for more data
        return

      let b0 = uint8(data[i]); inc i
      let b1 = uint8(data[i]); inc i

      p.fin    = (b0 shr 7) == 1
      p.opcode = int(b0 and 0x0F)
      p.masked = (b1 shr 7) == 1
      let len7 = b1 and 0x7F

      if not p.masked:
        ws.closeWs(1002, "Unmasked frame from client")
        return

      if p.opcode in {0x8, 0x9, 0xA} and len7 > MaxControlPayload:
        ws.closeWs(1002, "Control frame too large")
        return

      if len7 < 126:
        p.payloadLen = uint64(len7)
        if p.masked:
          p.phase = WsPhaseMask
          p.maskIdx = 0
        elif p.payloadLen == 0:
          p.phase = WsPhaseReady
        else:
          p.phase = WsPhasePayload
          if int(p.payloadLen) > p.payload.len:
            p.payload = newSeq[byte](int(p.payloadLen))
          p.payloadOff = 0
      elif len7 == 126:
        p.phase = WsPhaseLength16
        p.lengthIdx = 0
      else: # 127
        p.phase = WsPhaseLength64
        p.lengthIdx = 0

    of WsPhaseLength16:
      while p.lengthIdx < 2 and i < dataLen:
        p.lengthBuf[p.lengthIdx] = uint8(data[i])
        inc p.lengthIdx
        inc i
      if p.lengthIdx == 2:
        p.payloadLen = (uint64(p.lengthBuf[0]) shl 8) or uint64(p.lengthBuf[1])
        if p.payloadLen > frameLimit:
          ws.closeWs(1009, "Frame too large")
          return
        if p.opcode in {0x8, 0x9, 0xA} and p.payloadLen > MaxControlPayload:
          ws.closeWs(1002, "Control frame too large")
          return
        if p.masked:
          p.phase = WsPhaseMask
          p.maskIdx = 0
        elif p.payloadLen == 0:
          p.phase = WsPhaseReady
        else:
          p.phase = WsPhasePayload
          if int(p.payloadLen) > p.payload.len:
            p.payload = newSeq[byte](int(p.payloadLen))
          p.payloadOff = 0

    of WsPhaseLength64:
      while p.lengthIdx < 8 and i < dataLen:
        p.lengthBuf[p.lengthIdx] = uint8(data[i])
        inc p.lengthIdx
        inc i
      if p.lengthIdx == 8:
        var v: uint64 = 0
        for j in 0 ..< 8:
          v = (v shl 8) or uint64(p.lengthBuf[j])
        p.payloadLen = v
        if p.payloadLen > frameLimit:
          ws.closeWs(1009, "Frame too large")
          return
        if p.opcode in {0x8, 0x9, 0xA} and p.payloadLen > MaxControlPayload:
          ws.closeWs(1002, "Control frame too large")
          return
        if p.masked:
          p.phase = WsPhaseMask
          p.maskIdx = 0
        elif p.payloadLen == 0:
          p.phase = WsPhaseReady
        else:
          p.phase = WsPhasePayload
          if int(p.payloadLen) > p.payload.len:
            p.payload = newSeq[byte](int(p.payloadLen))
          p.payloadOff = 0

    of WsPhaseMask:
      while p.maskIdx < 4 and i < dataLen:
        p.maskKey[p.maskIdx] = uint8(data[i])
        inc p.maskIdx
        inc i
      if p.maskIdx == 4:
        if p.payloadLen > frameLimit:
          ws.closeWs(1009, "Frame too large")
          return
        if p.opcode in {0x8, 0x9, 0xA} and p.payloadLen > MaxControlPayload:
          ws.closeWs(1002, "Control frame too large")
          return
        if p.payloadLen == 0:
          p.phase = WsPhaseReady
        else:
          p.phase = WsPhasePayload
          if int(p.payloadLen) > p.payload.len:
            p.payload = newSeq[byte](int(p.payloadLen))
          p.payloadOff = 0

    of WsPhasePayload:
      let remaining = int(p.payloadLen) - p.payloadOff
      let avail = dataLen - i
      let toCopy = min(remaining, avail)
      if toCopy > 0:
        if p.masked:
          let mk = p.maskKey
          var di = i
          var po = p.payloadOff
          let poEnd = po + toCopy
          while po + 4 <= poEnd:
            p.payload[po]   = uint8(data[di])   xor mk[po and 3]
            p.payload[po+1] = uint8(data[di+1]) xor mk[(po+1) and 3]
            p.payload[po+2] = uint8(data[di+2]) xor mk[(po+2) and 3]
            p.payload[po+3] = uint8(data[di+3]) xor mk[(po+3) and 3]
            po += 4; di += 4
          while po < poEnd:
            p.payload[po] = uint8(data[di]) xor mk[po and 3]
            inc po; inc di
          p.payloadOff = po
          i = di
        else:
          copyMem(addr p.payload[p.payloadOff], unsafeAddr data[i], toCopy)
          p.payloadOff += toCopy
          i += toCopy
      if p.payloadOff >= int(p.payloadLen):
        p.phase = WsPhaseReady

    of WsPhaseReady:
      dispatchFrame(ws, p)

  if ws.parser.phase == WsPhaseReady:
    # Frame ended exactly at data boundary — dispatch the pending frame
    dispatchFrame(ws, ws.parser)

# ── WsConnection lifecycle ───────────────────────────────────────────────────

proc newWsConnection*(conn: Connection; maxFrameSize: int = DefaultMaxFrameSize): WsConnection =
  ## Create a new WebSocket connection wrapping a TCP connection.
  WsConnection(
    conn:       conn,
    parser:     newWsFrameParser(),
    maxFrameSize: maxFrameSize,
    assembling: false,
    fragOpcode: 0,
    assembleBuf: @[],
    lastActive: monoMs(),
    idleTimer: TimerId(0),
    idleTimeoutMs: 0,
  )

proc resetWs(ws: WsConnection; conn: Connection; maxFrameSize: int) =
  ## Reset a pooled WsConnection for reuse with a new TCP connection.
  ws.conn = conn
  ws.maxFrameSize = maxFrameSize
  ws.onOpen = nil
  ws.onMessage = nil
  ws.onClose = nil
  ws.onError = nil
  ws.assembling = false
  ws.fragOpcode = 0
  ws.assembleBuf.setLen(0)
  ws.idleTimer = TimerId(0)
  ws.idleTimeoutMs = 0
  ws.lastActive = monoMs()
  ws.parser.reset()

proc acquireWsConnection(wss: WsServer, conn: Connection): WsConnection =
  ## Get a WsConnection for `conn`, recycling one from the pool when available.
  if wss.wsPool.len > 0:
    result = wss.wsPool.pop()
    result.resetWs(conn, wss.maxFrameSize)
  else:
    result = newWsConnection(conn, wss.maxFrameSize)

proc releaseWsConnection(wss: WsServer, ws: WsConnection) =
  ## Return `ws` to the server's pool. Must be called exactly once per
  ## connection from the fd callback / server close paths. The idle timer is
  ## cancelled first so a stale wheel entry can never close a recycled
  ## connection or keep the object alive.
  if ws.idleTimer != TimerId(0):
    ws.conn.loop.cancelTimer(ws.idleTimer)
    ws.idleTimer = TimerId(0)
  if wss.wsPool.len < MaxWsPoolSize:
    ws.conn = nil
    ws.onOpen = nil
    ws.onMessage = nil
    ws.onClose = nil
    ws.onError = nil
    wss.wsPool.add(ws)

proc acquireWs(server: HttpServer, conn: Connection,
               maxFrameSize: int): WsConnection =
  ## Get a WsConnection for the HTTP→WS upgrade path, recycling one from the
  ## HttpServer pool when available. `server` may be nil (no pooling).
  if server != nil:
    let pooled = server.wsPoolPop()
    if pooled != nil:
      result = cast[WsConnection](pooled)
      result.resetWs(conn, maxFrameSize)
      return
  result = newWsConnection(conn, maxFrameSize)

proc releaseWs(server: HttpServer, ws: WsConnection) =
  ## Return `ws` to the HttpServer pool (upgrade path). `ws.conn == nil` marks
  ## it as already released, guarding against double-release. The idle timer is
  ## cancelled first so a stale wheel entry can never fire on a recycled object.
  if ws.conn == nil: return
  if ws.idleTimer != TimerId(0):
    ws.conn.loop.cancelTimer(ws.idleTimer)
    ws.idleTimer = TimerId(0)
  ws.conn = nil
  ws.onOpen = nil
  ws.onMessage = nil
  ws.onClose = nil
  ws.onError = nil
  if server != nil:
    server.wsPoolAdd(cast[ref RootObj](ws))

proc armIdleTimeout(ws: WsConnection) =
  ## Arm (or re-arm) the post-upgrade idle timer so it fires `idleTimeoutMs`
  ## after the last received frame. The timer only re-arms when it fires, so a
  ## busy connection does not churn the timer wheel on every frame.
  let timeout = ws.idleTimeoutMs
  if timeout <= 0: return
  if ws.idleTimer != TimerId(0):
    ws.conn.loop.cancelTimer(ws.idleTimer)
  let elapsed = int(min(int64(timeout), monoMs() - ws.lastActive))
  ws.idleTimer = ws.conn.loop.addTimer(max(timeout - elapsed, 1)) do (id: int):
    ws.idleTimer = TimerId(0)
    if ws.conn.state != Connected: return
    if monoMs() - ws.lastActive >= ws.idleTimeoutMs:
      ws.closeWs(1001, "Idle timeout")
    else:
      ws.armIdleTimeout()

# ── Standalone WsServer ──────────────────────────────────────────────────────

func headerValue(headers: HttpHeaders, key: string): string {.inline.} =
  ## Get a header value or "" if not present.
  if headers.hasKey(key):
    let vals = headers[key]
    if vals.len > 0: return vals
  return ""

proc newWsServer*(loop: Loop; maxFrameSize: int = DefaultMaxFrameSize): WsServer =
  ## Create a standalone WebSocket server. Register callbacks then call listen().
  WsServer(
    tcpServer: nil,
    loop:      loop,
    conns:     initTable[int, WsConnection](64),
    wsPool:    @[],
    maxFrameSize: maxFrameSize,
    handshakeSessions: initTable[int, HttpParser](64),
    handshakeTimers:   initTable[int, TimerId](64),
    handshakeTimeoutMs: 0,   # set to DefaultHandshakeTimeoutMs at listen()
    maxHandshakeSessions: 0,
  )

proc newWsServer*(maxFrameSize: int = DefaultMaxFrameSize): WsServer =
  ## Create a standalone WebSocket server with its own event loop.
  newWsServer(newLoop(), maxFrameSize)

proc start*(wss: WsServer) =
  ## Start the server's event loop. Blocks until the loop is stopped.
  wss.loop.run()

proc onOpen*(wss: WsServer, cb: WsOpenCb) =
  ## Set the callback for new WebSocket connections.
  wss.defaultOpen = cb

proc onMessage*(wss: WsServer, cb: WsMessageCb) =
  ## Set the callback for incoming messages.
  wss.defaultMessage = cb

proc onClose*(wss: WsServer, cb: WsCloseCb) =
  ## Set the callback for closed connections.
  wss.defaultClose = cb

proc onError*(wss: WsServer, cb: WsErrorCb) =
  ## Set the callback for errors.
  wss.defaultError = cb

const DefaultHandshakeTimeoutMs = 10_000

proc handshakeCount*(wss: WsServer): int {.inline.} =
  ## Number of connections currently in the HTTP→WebSocket handshake phase.
  wss.handshakeSessions.len

proc armHandshakeTimeout(wss: WsServer, conn: Connection) =
  ## Arm a timer that closes the connection if the HTTP→WebSocket handshake
  ## does not complete in time (slowloris-style handshake-stall defense).
  let fd = conn.fd.int
  if wss.handshakeTimeoutMs <= 0: return
  if fd in wss.handshakeTimers:
    wss.loop.cancelTimer(wss.handshakeTimers[fd])
  wss.handshakeTimers[fd] = wss.loop.addTimer(wss.handshakeTimeoutMs) do (id: int):
    wss.handshakeTimers.del(fd)
    if fd notin wss.handshakeSessions:
      return  # handshake already completed
    wss.handshakeSessions.del(fd)
    conn.close()

proc endHandshake(wss: WsServer, fd: int) =
  ## Tear down a handshake session (and its timeout timer).
  wss.handshakeSessions.del(fd)
  if fd in wss.handshakeTimers:
    wss.loop.cancelTimer(wss.handshakeTimers[fd])
    wss.handshakeTimers.del(fd)

proc listen*(wss: WsServer, address: string, port: int) =
  ## Bind and start accepting WebSocket connections on a dedicated port.
  # We need per-connection HTTP parsers for the handshake phase.
  if wss.handshakeTimeoutMs == 0:
    wss.handshakeTimeoutMs = DefaultHandshakeTimeoutMs

  wss.tcpServer = newTcpServer(wss.loop,
    onAccept = proc(conn: Connection) =
      let fd = conn.fd.int
      # Bound the number of in-flight handshakes (handshake-stall DoS defense)
      if wss.maxHandshakeSessions > 0 and
         wss.handshakeSessions.len >= wss.maxHandshakeSessions:
        conn.close()
        return
      wss.handshakeSessions[fd] = newHttpParser()
      wss.armHandshakeTimeout(conn)
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      let fd = conn.fd.int

      if fd in wss.conns:
        # Already upgraded — parse WebSocket frames
        wss.conns[fd].parseWsFrames(data)
        return

      # Not yet upgraded — feed into HTTP parser for handshake
      if fd notin wss.handshakeSessions:
        wss.handshakeSessions[fd] = newHttpParser()
        wss.armHandshakeTimeout(conn)

      let parser = addr wss.handshakeSessions[fd]
      let phase = parser[].feed(data)

      if parser[].isComplete():
        let req = parser[].getRequest()
        let headers = req.getHeaders()

        let clientKey = headerValue(headers, "Sec-WebSocket-Key")
        let upgradeHeader = headerValue(headers, "Upgrade")
        let wsVersion = headerValue(headers, "Sec-WebSocket-Version")
        if clientKey.len == 0 or upgradeHeader.toLowerAscii() != "websocket" or
           wsVersion != "13":
          discard conn.send("HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request")
          conn.close()
          wss.endHandshake(fd)
          return

        # Check if there are remaining bytes after the HTTP headers
        let remaining = parser[].getRemainingData()

        # Clean up the HTTP parser session
        wss.endHandshake(fd)

        # Send 101 Switching Protocols
        conn.sendHandshake(clientKey)

        # Create the WebSocket connection
        let ws = wss.acquireWsConnection(conn)
        ws.onOpen    = wss.defaultOpen
        ws.onMessage = wss.defaultMessage
        ws.onClose   = wss.defaultClose
        ws.onError   = wss.defaultError
        ws.idleTimeoutMs = wss.idleTimeoutMs
        ws.armIdleTimeout()

        wss.conns[fd] = ws

        # Re-register fd for raw WebSocket frame handling
        conn.loop.unregister(fd)
        conn.loop.register(fd, {Read}, edgeTriggered = true,
          callback = proc(efd: int, ev: set[EventType]) =
            if ws.conn == nil: return
            if Error in ev or Hup in ev:
              if not ws.onClose.isNil:
                ws.onClose(ws, 1006, "Connection lost")
              ws.conn.close()
              if efd in wss.conns:
                wss.conns.del(efd)
                wss.releaseWsConnection(ws)
              return
            if Write in ev:
              if ws.conn.flushWriteBuffer():
                if ws.conn.state == Connected:
                  ws.conn.loop.modify(efd, {Read})
            if Read in ev:
              var buf: array[65536, byte]
              while true:
                when defined(windows):
                  let n = ws.conn.loop.platform.getReadData(
                    ws.conn.fd.int,
                    cast[ptr UncheckedArray[byte]](addr buf[0]), buf.len)
                  if n > 0:
                    ws.parseWsFrames(buf.toOpenArray(0, n - 1))
                    if ws.conn.state != Connected:
                      if efd in wss.conns:
                        wss.conns.del(efd)
                        wss.releaseWsConnection(ws)
                      return
                  else:
                    break
                else:
                  let n = sockRecv(ws.conn.fd, addr buf[0], buf.len)
                  if n > 0:
                    ws.parseWsFrames(buf.toOpenArray(0, n - 1))
                    if ws.conn.state != Connected:
                      if efd in wss.conns:
                        wss.conns.del(efd)
                        wss.releaseWsConnection(ws)
                      return
                  elif n == 0:
                    if not ws.onClose.isNil:
                      ws.onClose(ws, 1000, "")
                    ws.conn.close()
                    if efd in wss.conns:
                      wss.conns.del(efd)
                      wss.releaseWsConnection(ws)
                    return
                  else:
                    if sockWouldBlock():
                      break
                    if sockInterrupted():
                      continue
                    if not ws.onError.isNil:
                      ws.onError(ws, "recv error: " & $lastSocketError())
                    ws.conn.close()
                    if efd in wss.conns:
                      wss.conns.del(efd)
                      wss.releaseWsConnection(ws)
                    return
        )

        # Fire onOpen
        if not ws.onOpen.isNil:
          ws.onOpen(ws)

        # Process any remaining bytes from the initial TCP read
        if remaining.len > 0:
          ws.parseWsFrames(remaining)

      elif parser[].isError():
        let badRequest = "Bad Request"
        discard conn.send("HTTP/1.1 400 Bad Request\r\nContent-Length: "& $(badRequest.len) & "\r\n\r\n" & badRequest)
        conn.close()
        wss.endHandshake(fd)
    ,
    onClose = proc(conn: Connection) =
      let fd = conn.fd.int
      wss.endHandshake(fd)
      if fd in wss.conns:
        let ws = wss.conns[fd]
        if not ws.onClose.isNil:
          ws.onClose(ws, 1000, "")
        wss.conns.del(fd)
        wss.releaseWsConnection(ws)
    ,
  )
  wss.tcpServer.listen(address, port)

proc close*(wss: WsServer) =
  ## Shut down the WebSocket server.
  if wss.tcpServer != nil:
    wss.tcpServer.close()
  for fd, id in wss.handshakeTimers:
    wss.loop.cancelTimer(id)
  wss.handshakeTimers.clear()
  wss.handshakeSessions.clear()
  for fd, ws in wss.conns:
    if ws.idleTimer != TimerId(0):
      wss.loop.cancelTimer(ws.idleTimer)
    if not ws.onClose.isNil:
      ws.onClose(ws, 1001, "Server shutting down")
    ws.conn.close()
    wss.releaseWsConnection(ws)
  wss.conns.clear()
  wss.wsPool.setLen(0)

# ── HTTP → WebSocket upgrade ─────────────────────────────────────────────────

proc websocketUpgrade*(
    res: HttpResponse,
    req: HttpRequest,
    server: HttpServer = nil,
    onOpen: WsOpenCb = nil,
    onMessage: WsMessageCb = nil,
    onClose: WsCloseCb = nil,
    onError: WsErrorCb = nil,
    maxFrameSize: int = DefaultMaxFrameSize
): WsConnection {.gcsafe, discardable.} =
  ## Upgrade an HTTP connection to WebSocket. Call this from an HTTP route handler.
  ##
  ## After the upgrade, the connection is no longer managed by the HttpServer —
  ## all future data goes directly to the WebSocket callbacks.
  ##
  ## The `server` argument is optional: it is derived from the response when
  ## omitted, so the connection is always detached from the HTTP session
  ## tracking and the post-upgrade idle timeout applies.
  ##
  ## .. code-block:: nim
  ##    server.get("/ws") do (req: HttpRequest, res: Response):
  ##      let ws = websocketUpgrade(res, req, server,
  ##        onOpen = proc(ws: WsConnection) = echo "open!",
  ##        onMessage = proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
  ##          ws.sendText(cast[string](@data)),
  ##      )
  {.gcsafe.}:
    var owner = server
    let headers = req.getHeaders()
    let clientKey = headerValue(headers, "Sec-WebSocket-Key")
    let upgradeHeader = headerValue(headers, "Upgrade")
    let wsVersion = headerValue(headers, "Sec-WebSocket-Version")

    if clientKey.len == 0 or upgradeHeader.toLowerAscii() != "websocket" or
       wsVersion != "13":
      res.status(Http400)
        .send("Bad Request: missing WebSocket headers")
      return nil

    # Get the underlying connection before sending the handshake
    let conn = res.getConn()

    res.markSent()

    # The owning HttpServer can be derived from the response, so a route that
    # calls websocketUpgrade without passing `server` still detaches the
    # connection from the HTTP session tracking. Otherwise the server-wide
    # timeout sweep keeps treating the upgraded connection as an idle HTTP
    # connection and closes it out from under the WebSocket.
    if owner == nil:
      owner = res.server
    if owner != nil:
      owner.removeSession(conn)

    # Send the 101 Switching Protocols response
    conn.sendHandshake(clientKey)

    # Create WebSocket connection
    let ws = owner.acquireWs(conn, maxFrameSize)
    ws.onOpen    = onOpen
    ws.onMessage = onMessage
    ws.onClose   = onClose
    ws.onError   = onError
    if owner != nil:
      ws.idleTimeoutMs = owner.wsIdleTimeoutMs
      ws.armIdleTimeout()

    # Re-register the fd for raw WebSocket frame handling.
    # We need to unregister the old HTTP handler first.
    conn.loop.unregister(conn.fd.int)
    conn.loop.register(conn.fd.int, {Read}, edgeTriggered = true,
      callback = proc(fd: int, ev: set[EventType]) =
        # The ws may already be released (conn detached) if a stale event slips
        # through — never dereference a nil connection.
        if ws.conn == nil: return
        if Error in ev or Hup in ev:
          if not ws.onClose.isNil:
            ws.onClose(ws, 1006, "Connection lost")
          ws.conn.close()
          owner.releaseWs(ws)
          return
        if Write in ev:
          # A buffered frame write (sendText armed {Read, Write}) needs flushing;
          # without this the ws send stalls forever under socket backpressure.
          if ws.conn.flushWriteBuffer():
            if ws.conn.state == Connected:
              ws.conn.loop.modify(fd, {Read})
        if Read in ev:
          var buf: array[65536, byte]
          while true:
            when defined(windows):
              let n = ws.conn.loop.platform.getReadData(
                ws.conn.fd.int,
                cast[ptr UncheckedArray[byte]](addr buf[0]), buf.len)
              if n > 0:
                ws.parseWsFrames(buf.toOpenArray(0, n - 1))
                if ws.conn.state != Connected:
                  owner.releaseWs(ws)
                  return
              else:
                break
            else:
              let n = sockRecv(ws.conn.fd, addr buf[0], buf.len)
              if n > 0:
                ws.parseWsFrames(buf.toOpenArray(0, n - 1))
                if ws.conn.state != Connected:
                  owner.releaseWs(ws)
                  return
              elif n == 0:
                if not ws.onClose.isNil:
                  ws.onClose(ws, 1000, "")
                ws.conn.close()
                owner.releaseWs(ws)
                return
              else:
                if sockWouldBlock():
                  break
                if sockInterrupted():
                  continue
                if not ws.onError.isNil:
                  ws.onError(ws, "recv error: " & $lastSocketError())
                ws.conn.close()
                owner.releaseWs(ws)
                return
    )

    # Fire onOpen
    if not ws.onOpen.isNil:
      ws.onOpen(ws)

    return ws
