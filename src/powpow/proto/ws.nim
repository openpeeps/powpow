# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
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

import std/[httpcore, sha1, base64, tables, strutils, posix]

import ../net/tcp
import ../loop
import ../types
import ../proto/http
import ../proto/httpserver

# ── Constants ────────────────────────────────────────────────────────────────

const
  wsGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  MaxControlPayload = 125      ## Max payload for control frames (RFC 6455 §5.5)
  DefaultWsBufSize  = 65536    ## Initial frame parser buffer

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

  WsConnection* = ref object
    ## A WebSocket connection. Wraps a TCP connection with frame
    ## parsing, fragmentation reassembly, and control frame handling.
    conn*:       Connection       ## Underlying TCP connection
    parser:      WsFrameParser    ## Incremental frame parser
    onMessage:   WsMessageCb
    onClose:     WsCloseCb
    onError:     WsErrorCb
    onOpen:      WsOpenCb
    # Fragmentation reassembly
    assembling:  bool
    fragOpcode:  int
    assembleBuf: seq[byte]

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
    # User callbacks (applied to all connections)
    defaultOpen:    WsOpenCb
    defaultMessage: WsMessageCb
    defaultClose:   WsCloseCb
    defaultError:   WsErrorCb

# ── Frame parser ─────────────────────────────────────────────────────────────

proc newWsFrameParser(): WsFrameParser =
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

proc computeAcceptKey*(clientKey: string): string =
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
           "Server: powpow/0.1.0\r\n" &
           "\r\n"

proc sendHandshake*(conn: Connection, clientKey: string) =
  ## Send the HTTP 101 upgrade response directly on the connection.
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
    header[1] = uint8(n)                         # no mask bit (server frames)
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

  discard conn.send(header.toOpenArray(0, hlen - 1))
  if n > 0:
    discard conn.send(payload)

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

  # Copy mask key into header
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

proc sendText*(ws: WsConnection, s: string) =
  ## Send a text message.
  if s.len == 0:
    ws.conn.writeFrame(0x1, [])
  else:
    ws.conn.writeFrame(0x1, s.toOpenArrayByte(0, s.high))

proc sendBinary*(ws: WsConnection, data: openArray[byte]) =
  ## Send a binary message.
  if data.len == 0:
    ws.conn.writeFrame(0x2, [])
  else:
    ws.conn.writeFrame(0x2, data)

proc sendPing*(ws: WsConnection, data: openArray[byte] = []) =
  ## Send a ping frame.
  if data.len == 0:
    ws.conn.writeFrame(0x9, [])
  else:
    ws.conn.writeFrame(0x9, data)

proc sendPong*(ws: WsConnection, data: openArray[byte] = []) =
  ## Send a pong frame (usually automatic, but exposed for manual use).
  if data.len == 0:
    ws.conn.writeFrame(0xA, [])
  else:
    ws.conn.writeFrame(0xA, data)

proc closeWs*(ws: WsConnection, code: int = 1000, reason: string = "") =
  ## Send a close frame and shut down the connection.
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

proc parseWsFrames(ws: WsConnection, data: openArray[byte]) =
  ## Feed incoming TCP data into the WebSocket frame parser.
  ## Dispatches complete frames to the appropriate callbacks.
  var i = 0
  let dataLen = data.len

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
          for j in 0 ..< toCopy:
            p.payload[p.payloadOff + j] =
              uint8(data[i + j]) xor p.maskKey[(p.payloadOff + j) mod 4]
        else:
          copyMem(addr p.payload[p.payloadOff], unsafeAddr data[i], toCopy)
        p.payloadOff += toCopy
        i += toCopy
      if p.payloadOff >= int(p.payloadLen):
        p.phase = WsPhaseReady

    of WsPhaseReady:
      # Dispatch the complete frame
      let opcode = p.opcode
      let plen = int(p.payloadLen)

      # Reset parser for next frame before dispatching (callbacks may feed more)
      p.phase = WsPhaseHeader

      case opcode
      of 0x0: # Continuation
        if not ws.assembling:
          if not ws.onError.isNil:
            ws.onError(ws, "Unexpected continuation frame")
          ws.closeWs(1002, "Protocol error")
          return
        if plen > 0:
          ws.assembleBuf.add p.payload.toOpenArray(0, plen - 1)
        if p.fin:
          let finalOp = ws.fragOpcode
          ws.assembling = false
          if not ws.onMessage.isNil:
            ws.onMessage(ws, WsFrameKind(finalOp), ws.assembleBuf)
          ws.assembleBuf.setLen(0)

      of 0x1, 0x2: # Text or Binary
        if p.fin:
          if not ws.onMessage.isNil:
            if plen > 0:
              ws.onMessage(ws, WsFrameKind(opcode), p.payload.toOpenArray(0, plen - 1))
            else:
              ws.onMessage(ws, WsFrameKind(opcode), [])
        else:
          # Start fragmentation
          ws.assembling = true
          ws.fragOpcode = opcode
          ws.assembleBuf.setLen(0)
          if plen > 0:
            ws.assembleBuf.add p.payload.toOpenArray(0, plen - 1)

      of 0x8: # Close
        var closeCode = 1000
        var reason = ""
        if plen >= 2:
          closeCode = (int(p.payload[0]) shl 8) or int(p.payload[1])
        if plen > 2:
          reason = newString(plen - 2)
          copyMem(addr reason[0], unsafeAddr p.payload[2], plen - 2)
        # Echo the close frame back
        if plen > 0:
          ws.conn.writeFrame(0x8, p.payload.toOpenArray(0, plen - 1))
        else:
          ws.conn.writeFrame(0x8, [])
        if not ws.onClose.isNil:
          ws.onClose(ws, closeCode, reason)
        ws.conn.close()
        return

      of 0x9: # Ping → auto Pong
        if plen > 0:
          ws.conn.writeFrame(0xA, p.payload.toOpenArray(0, plen - 1))
        else:
          ws.conn.writeFrame(0xA, [])

      of 0xA: # Pong → ignore
        discard

      else:
        if not ws.onError.isNil:
          ws.onError(ws, "Unsupported opcode: " & $opcode)
        ws.closeWs(1003, "Unsupported opcode")
        return

# ── WsConnection lifecycle ───────────────────────────────────────────────────

proc newWsConnection(conn: Connection): WsConnection =
  ## Create a new WebSocket connection wrapping a TCP connection.
  WsConnection(
    conn:       conn,
    parser:     newWsFrameParser(),
    assembling: false,
    fragOpcode: 0,
    assembleBuf: @[],
  )

# ── Standalone WsServer ──────────────────────────────────────────────────────

proc headerValue(headers: HttpHeaders, key: string): string {.inline.} =
  ## Get a header value or "" if not present.
  if headers.hasKey(key):
    let vals = headers[key]
    if vals.len > 0: return vals
  return ""

proc newWsServer*(loop: Loop): WsServer =
  ## Create a standalone WebSocket server. Register callbacks then call listen().
  WsServer(
    tcpServer: nil,
    loop:      loop,
    conns:     initTable[int, WsConnection](64),
  )

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

proc listen*(wss: WsServer, address: string, port: int) =
  ## Bind and start accepting WebSocket connections on a dedicated port.
  # We need per-connection HTTP parsers for the handshake phase.
  var handshakeSessions = initTable[int, HttpParser](64)

  wss.tcpServer = newTcpServer(wss.loop,
    onAccept = proc(conn: Connection) =
      handshakeSessions[conn.fd.int] = newHttpParser()
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      let fd = conn.fd.int

      if fd in wss.conns:
        # Already upgraded — parse WebSocket frames
        wss.conns[fd].parseWsFrames(data)
        return

      # Not yet upgraded — feed into HTTP parser for handshake
      if fd notin handshakeSessions:
        handshakeSessions[fd] = newHttpParser()

      let parser = addr handshakeSessions[fd]
      let phase = parser[].feed(data)

      if parser[].isComplete():
        let req = parser[].getRequest()
        let headers = req.getHeaders()

        let clientKey = headerValue(headers, "Sec-WebSocket-Key")
        let upgradeHeader = headerValue(headers, "Upgrade")
        if clientKey.len == 0 or upgradeHeader.toLowerAscii() != "websocket":
          discard conn.send("HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request")
          conn.close()
          handshakeSessions.del(fd)
          return

        # Check if there are remaining bytes after the HTTP headers
        let remaining = parser[].getRemainingData()

        # Clean up the HTTP parser session
        handshakeSessions.del(fd)

        # Send 101 Switching Protocols
        conn.sendHandshake(clientKey)

        # Create the WebSocket connection
        let ws = newWsConnection(conn)
        ws.onOpen    = wss.defaultOpen
        ws.onMessage = wss.defaultMessage
        ws.onClose   = wss.defaultClose
        ws.onError   = wss.defaultError

        wss.conns[fd] = ws

        # Re-register fd for raw WebSocket frame handling
        conn.loop.unregister(fd)
        conn.loop.register(fd, {Read}, edgeTriggered = true,
          callback = proc(efd: int, ev: set[EventType]) =
            if Error in ev or Hup in ev:
              if not ws.onClose.isNil:
                ws.onClose(ws, 1006, "Connection lost")
              ws.conn.close()
              wss.conns.del(efd)
              return
            if Read in ev:
              var buf: array[65536, byte]
              while true:
                let n = posix.recv(ws.conn.fd, addr buf[0], buf.len, 0)
                if n > 0:
                  ws.parseWsFrames(buf.toOpenArray(0, n - 1))
                  if ws.conn.state != Connected:
                    wss.conns.del(efd)
                    return
                elif n == 0:
                  if not ws.onClose.isNil:
                    ws.onClose(ws, 1000, "")
                  ws.conn.close()
                  wss.conns.del(efd)
                  return
                else:
                  if errno == EAGAIN or errno == EWOULDBLOCK:
                    break
                  if errno == EINTR:
                    continue
                  if not ws.onError.isNil:
                    ws.onError(ws, "recv error: " & $errno)
                  ws.conn.close()
                  wss.conns.del(efd)
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
        handshakeSessions.del(fd)
    ,
    onClose = proc(conn: Connection) =
      let fd = conn.fd.int
      handshakeSessions.del(fd)
      if fd in wss.conns:
        let ws = wss.conns[fd]
        if not ws.onClose.isNil:
          ws.onClose(ws, 1000, "")
        wss.conns.del(fd)
    ,
  )
  wss.tcpServer.listen(address, port)

proc close*(wss: WsServer) =
  ## Shut down the WebSocket server.
  if wss.tcpServer != nil:
    wss.tcpServer.close()
  wss.conns.clear()

# ── HTTP → WebSocket upgrade ─────────────────────────────────────────────────

proc websocketUpgrade*(
    res: HttpResponse,
    req: HttpRequest,
    server: HttpServer = nil,
    onOpen: WsOpenCb = nil,
    onMessage: WsMessageCb = nil,
    onClose: WsCloseCb = nil,
    onError: WsErrorCb = nil
): WsConnection {.gcsafe, discardable.} =
  ## Upgrade an HTTP connection to WebSocket. Call this from an HTTP route handler.
  ##
  ## After the upgrade, the connection is no longer managed by the HttpServer —
  ## all future data goes directly to the WebSocket callbacks.
  ##
  ## Pass the `server` argument to clean up the HTTP session tracking.
  ##
  ## .. code-block:: nim
  ##    server.get("/ws") do (req: HttpRequest, res: Response):
  ##      let ws = websocketUpgrade(res, req, server,
  ##        onOpen = proc(ws: WsConnection) = echo "open!",
  ##        onMessage = proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
  ##          ws.sendText(cast[string](@data)),
  ##      )
  {.gcsafe.}:
    let headers = req.getHeaders()
    let clientKey = headerValue(headers, "Sec-WebSocket-Key")
    let upgradeHeader = headerValue(headers, "Upgrade")

    if clientKey.len == 0 or upgradeHeader.toLowerAscii() != "websocket":
      res.status(Http400)
        .send("Bad Request: missing WebSocket headers")
      return nil

    # Get the underlying connection before sending the handshake
    let conn = res.getConn()

    res.markSent()

    if server != nil:
      server.removeSession(conn)

    # Send the 101 Switching Protocols response
    conn.sendHandshake(clientKey)

    # Create WebSocket connection
    let ws = newWsConnection(conn)
    ws.onOpen    = onOpen
    ws.onMessage = onMessage
    ws.onClose   = onClose
    ws.onError   = onError

    # Re-register the fd for raw WebSocket frame handling.
    # We need to unregister the old HTTP handler first.
    conn.loop.unregister(conn.fd.int)
    conn.loop.register(conn.fd.int, {Read}, edgeTriggered = true,
      callback = proc(fd: int, ev: set[EventType]) =
        if Error in ev or Hup in ev:
          if not ws.onClose.isNil:
            ws.onClose(ws, 1006, "Connection lost")
          ws.conn.close()
          return
        if Read in ev:
          var buf: array[65536, byte]
          while true:
            let n = posix.recv(ws.conn.fd, addr buf[0], buf.len, 0)
            if n > 0:
              ws.parseWsFrames(buf.toOpenArray(0, n - 1))
              if ws.conn.state != Connected:
                return
            elif n == 0:
              if not ws.onClose.isNil:
                ws.onClose(ws, 1000, "")
              ws.conn.close()
              return
            else:
              if errno == EAGAIN or errno == EWOULDBLOCK:
                break
              if errno == EINTR:
                continue
              if not ws.onError.isNil:
                ws.onError(ws, "recv error: " & $errno)
              ws.conn.close()
              return
    )

    # Fire onOpen
    if not ws.onOpen.isNil:
      ws.onOpen(ws)

    return ws
