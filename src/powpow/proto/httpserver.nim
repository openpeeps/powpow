# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## A non-blocking HTTP/1.1 server built on top of powpow's TCP primitives.
## 
## Combines the TCP transport layer with the incremental HTTP parser
## to provide a high-level routing server with minimal overhead.
##
## Usage:
##   let server = newHttpServer(loop)
##   server.get("/") do (req: HttpRequest, res: Response):
##     res.status(Http200).send("Hello!")
##   server.listen("0.0.0.0", 8080)
##   loop.run()

import ../net/tcp
import ../net/common
import ../loop
import ../types
import http
import std/[httpcore, tables, options, strutils, os, posix]
import pkg/mimedb

# ── Types ────────────────────────────────────────────────────────────────────

type
  Response* = ref object
    ## Build and send an HTTP response.
    conn:       Connection
    sent:       bool
    statusCode: HttpCode
    headers:    seq[(string, string)]
    bodyBytes:  seq[byte]
    closeConn:  bool           ## If true, send "Connection: close" and shut down

  Handler* = proc(req: HttpRequest, res: Response) {.closure.}
    ## Route handler. Call `res.status(...).send(...)` to respond.

  # RouteKey = object
  #   httpMethod: HttpMethod
  #   path:   string

  Session = object
    ## Per-connection state.
    parser: HttpParser
    idleTimer: TimerId
    idleMs:    int

  HttpServer* = ref object
    ## A non-blocking HTTP/1.1 server.
    tcpServer: TcpServer
    loop:      Loop
    routes:    Table[HttpMethod, Table[string, Handler]]  ## method → path → handler
    fallback:  Handler                      ## Catch-all handler (nil = 404)
    sessions:  Table[int, Session]          ## fd → parser session
    parserPool: seq[HttpParser]             ## recycled parser objects
    resPool:   seq[Response]                ## recycled response objects
    keepAliveMs: int

const
  DefaultKeepAliveMs* = 5_000
  ServerHeader = "Server: powpow/0.1.0\r\n"
  MaxParserPoolSize = 2048
  MaxResPoolSize = 4048



proc getFileExt*(path: string): string =
  ## Extract the lowercase file extension from a path.
  let (_, _, ext) = path.splitFile()
  result = ext.toLowerAscii()

proc parseRange*(rangeHeader: string; fileSize: int64): tuple[ok: bool; start, length: int64] =
  ## Parse an HTTP Range header (single range, `bytes=start-end`).
  ## Supports explicit ranges (`0-1023`), open-ended ranges (`1024-`),
  ## and suffix ranges (`-500`). Clamps rangeEnd to fileSize - 1.
  ## Returns (true, startByte, length) on success, (false, 0, 0) on failure.
  if not rangeHeader.startsWith("bytes="):
    return (false, 0, 0)
  if fileSize <= 0:
    return (false, 0, 0)
  let range = rangeHeader[6..^1]
  let parts = range.split('-')
  if parts.len != 2:
    return (false, 0, 0)
  let startStr = parts[0].strip()
  let endStr = parts[1].strip()

  var rangeStart = 0i64
  var rangeEnd = fileSize - 1

  if startStr.len > 0 and endStr.len > 0:
    # Explicit range: bytes=start-end
    try:
      rangeStart = parseInt(startStr).int64
      rangeEnd = parseInt(endStr).int64
    except ValueError:
      return (false, 0, 0)
    if rangeStart > rangeEnd or rangeStart < 0:
      return (false, 0, 0)
    if rangeStart >= fileSize:
      return (false, 0, 0)
    if rangeEnd >= fileSize:
      rangeEnd = fileSize - 1
  elif startStr.len > 0:
    # Open-ended range: bytes=start-
    try:
      rangeStart = parseInt(startStr).int64
    except ValueError:
      return (false, 0, 0)
    if rangeStart < 0 or rangeStart >= fileSize:
      return (false, 0, 0)
    rangeEnd = fileSize - 1
  elif endStr.len > 0:
    # Suffix range: bytes=-length (last N bytes)
    try:
      let suffixLen = parseInt(endStr).int64
      if suffixLen <= 0:
        return (false, 0, 0)
      if suffixLen >= fileSize:
        rangeStart = 0
      else:
        rangeStart = fileSize - suffixLen
      rangeEnd = fileSize - 1
    except ValueError:
      return (false, 0, 0)
  else:
    return (false, 0, 0)

  result = (true, rangeStart, rangeEnd - rangeStart + 1)

# ── Response ─────────────────────────────────────────────────────────────────

proc newResponse(conn: Connection): Response =
  Response(
    conn:       conn,
    sent:       false,
    statusCode: Http200,
    headers:    @[],
    bodyBytes:  @[],
    closeConn:  false,
  )

proc status*(res: Response, code: HttpCode): Response {.discardable.} =
  ## Set the HTTP status code.
  res.statusCode = code
  return res

proc header*(res: Response, key, value: string): Response {.discardable.} =
  ## Add a response header.
  res.headers.add((key, value))
  return res

proc close*(res: Response): Response {.discardable.} =
  ## Mark this response to send "Connection: close" and shut down the
  ## TCP connection after the response is sent.
  res.closeConn = true
  return res

proc statusText(code: HttpCode): string {.inline.} =
  ## Return the HTTP reason phrase for a status code.
  ## Returns a string literal (no heap allocation).
  case code.int
  of 100: "Continue"
  of 101: "Switching Protocols"
  of 200: "OK"
  of 201: "Created"
  of 202: "Accepted"
  of 204: "No Content"
  of 206: "Partial Content"
  of 301: "Moved Permanently"
  of 302: "Found"
  of 304: "Not Modified"
  of 307: "Temporary Redirect"
  of 308: "Permanent Redirect"
  of 400: "Bad Request"
  of 401: "Unauthorized"
  of 403: "Forbidden"
  of 404: "Not Found"
  of 405: "Method Not Allowed"
  of 408: "Request Timeout"
  of 409: "Conflict"
  of 410: "Gone"
  of 411: "Length Required"
  of 413: "Payload Too Large"
  of 414: "URI Too Long"
  of 415: "Unsupported Media Type"
  of 416: "Range Not Satisfiable"
  of 429: "Too Many Requests"
  of 500: "Internal Server Error"
  of 501: "Not Implemented"
  of 502: "Bad Gateway"
  of 503: "Service Unavailable"
  of 504: "Gateway Timeout"
  of 505: "HTTP Version Not Supported"
  else: "Unknown"

proc writeUint(buf: ptr UncheckedArray[byte], n: int64): int =
  if n == 0:
    buf[0] = byte('0')
    return 1
  var tmp = n
  var digits: array[20, byte]
  var ndigits = 0
  while tmp > 0:
    digits[ndigits] = byte(ord('0') + tmp mod 10)
    inc ndigits
    tmp = tmp div 10
  for i in 0 ..< ndigits:
    buf[i] = digits[ndigits - 1 - i]
  return ndigits

proc send*(res: Response, body: string = "") =
  ## Send the response with a string body.
  ## Uses scatter-write (writev) to send headers + body with zero
  ## intermediate string allocations.
  if res.sent: return
  res.sent = true
  let connHeader = if res.closeConn: "close" else: "keep-alive"

  # Write fixed header parts into a stack buffer (zero heap allocation)
  var hdrBuf: array[256, byte]
  var p = 0

  # Status line: "HTTP/1.1 200 OK\r\n"
  copyMem(addr hdrBuf[p], "HTTP/1.1 ".cstring, 9); p += 9
  p += writeUint(cast[ptr UncheckedArray[byte]](addr hdrBuf[p]), res.statusCode.int)
  hdrBuf[p] = byte(' '); p += 1
  let stext = statusText(res.statusCode)
  copyMem(addr hdrBuf[p], stext.cstring, stext.len); p += stext.len
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  # Content-Length
  copyMem(addr hdrBuf[p], "Content-Length: ".cstring, 16); p += 16
  p += writeUint(cast[ptr UncheckedArray[byte]](addr hdrBuf[p]), body.len)
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  # Connection
  copyMem(addr hdrBuf[p], "Connection: ".cstring, 12); p += 12
  copyMem(addr hdrBuf[p], connHeader.cstring, connHeader.len); p += connHeader.len
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  # Server
  copyMem(addr hdrBuf[p], ServerHeader.cstring, ServerHeader.len); p += ServerHeader.len

  # Build scatter-write iovec array
  type Part = tuple[data: ptr UncheckedArray[byte], len: int]
  const MaxParts = 150
  let numParts = 1 + res.headers.len * 4 + 1 + (if body.len > 0: 1 else: 0)

  template scatterWrite(parts: var openArray[Part], count: var int) =
    parts[count] = (cast[ptr UncheckedArray[byte]](addr hdrBuf[0]), p); inc count
    for (k, v) in res.headers:
      parts[count] = (cast[ptr UncheckedArray[byte]](k.cstring), k.len); inc count
      parts[count] = (cast[ptr UncheckedArray[byte]](": ".cstring), 2); inc count
      parts[count] = (cast[ptr UncheckedArray[byte]](v.cstring), v.len); inc count
      parts[count] = (cast[ptr UncheckedArray[byte]]("\r\n".cstring), 2); inc count
    parts[count] = (cast[ptr UncheckedArray[byte]]("\r\n".cstring), 2); inc count
    if body.len > 0:
      parts[count] = (cast[ptr UncheckedArray[byte]](unsafeAddr body[0]), body.len); inc count

  if numParts <= MaxParts:
    var parts: array[MaxParts, Part]
    var count = 0
    scatterWrite(parts, count)
    discard res.conn.sendv(parts.toOpenArray(0, count - 1))
  else:
    var parts = newSeq[Part](numParts)
    var count = 0
    scatterWrite(parts, count)
    discard res.conn.sendv(parts.toOpenArray(0, count - 1))

  if res.closeConn:
    res.conn.closeAfterDrain()

proc send*(res: Response, body: seq[byte]) =
  ## Send the response with a raw byte body.
  ## Uses scatter-write (writev) to send headers + body with zero
  ## intermediate string allocations.
  if res.sent: return
  res.sent = true
  let connHeader = if res.closeConn: "close" else: "keep-alive"

  # Write fixed header parts into a stack buffer (zero heap allocation)
  var hdrBuf: array[256, byte]
  var p = 0

  # Status line: "HTTP/1.1 200 OK\r\n"
  copyMem(addr hdrBuf[p], "HTTP/1.1 ".cstring, 9); p += 9
  p += writeUint(cast[ptr UncheckedArray[byte]](addr hdrBuf[p]), res.statusCode.int)
  hdrBuf[p] = byte(' '); p += 1
  let stext = statusText(res.statusCode)
  copyMem(addr hdrBuf[p], stext.cstring, stext.len); p += stext.len
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  # Content-Length
  copyMem(addr hdrBuf[p], "Content-Length: ".cstring, 16); p += 16
  p += writeUint(cast[ptr UncheckedArray[byte]](addr hdrBuf[p]), body.len)
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  # Connection
  copyMem(addr hdrBuf[p], "Connection: ".cstring, 12); p += 12
  copyMem(addr hdrBuf[p], connHeader.cstring, connHeader.len); p += connHeader.len
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  # Server
  copyMem(addr hdrBuf[p], ServerHeader.cstring, ServerHeader.len); p += ServerHeader.len

  # Build scatter-write iovec array
  type Part = tuple[data: ptr UncheckedArray[byte], len: int]
  const MaxParts = 150
  let numParts = 1 + res.headers.len * 4 + 1 + (if body.len > 0: 1 else: 0)

  template scatterWrite(parts: var openArray[Part], count: var int) =
    parts[count] = (cast[ptr UncheckedArray[byte]](addr hdrBuf[0]), p); inc count
    for (k, v) in res.headers:
      parts[count] = (cast[ptr UncheckedArray[byte]](k.cstring), k.len); inc count
      parts[count] = (cast[ptr UncheckedArray[byte]](": ".cstring), 2); inc count
      parts[count] = (cast[ptr UncheckedArray[byte]](v.cstring), v.len); inc count
      parts[count] = (cast[ptr UncheckedArray[byte]]("\r\n".cstring), 2); inc count
    parts[count] = (cast[ptr UncheckedArray[byte]]("\r\n".cstring), 2); inc count
    if body.len > 0:
      parts[count] = (cast[ptr UncheckedArray[byte]](unsafeAddr body[0]), body.len); inc count

  if numParts <= MaxParts:
    var parts: array[MaxParts, Part]
    var count = 0
    scatterWrite(parts, count)
    discard res.conn.sendv(parts.toOpenArray(0, count - 1))
  else:
    var parts = newSeq[Part](numParts)
    var count = 0
    scatterWrite(parts, count)
    discard res.conn.sendv(parts.toOpenArray(0, count - 1))

  if res.closeConn:
    res.conn.closeAfterDrain()

proc writeDisposition*(buf: ptr UncheckedArray[byte]; name: string; p: var int) =
  copyMem(addr buf[p], "Content-Disposition: attachment; filename=\"".cstring, 43); p += 43
  copyMem(addr buf[p], name.cstring, name.len); p += name.len
  copyMem(addr buf[p], "\"\r\n".cstring, 3); p += 3

proc sendFile*(res: Response, path: string;
               req: HttpRequest = default(HttpRequest);
               closeConn = true) =
  ## Send a file for download using zero-copy when possible.
  ## Adds `Content-Disposition: attachment; filename="..."`.
  ## Supports HTTP Range requests when `req` is provided.
  ## `closeConn` controls connection lifetime: true (default) closes after
  ## the transfer; false keeps the connection alive.
  if res.sent: return

  let fileFd = openFileRead(path)
  if fileFd < 0:
    res.status(Http404).send("File not found")
    return

  var fileSize = getFileSize(fileFd)
  if fileSize < 0:
    closeFile(fileFd)
    res.status(Http404).send("File not found")
    return

  var rangeStart = 0i64
  var rangeLen = fileSize
  var status = Http200

  if req != default(HttpRequest):
    let headers = req.getHeaders()
    if headers.hasKey("range"):
      let rangeVal = headers["range"].toLowerAscii()
      let r = parseRange(rangeVal, fileSize)
      if r.ok:
        rangeStart = r.start
        rangeLen = r.length
        status = Http206
      elif rangeVal.startsWith("bytes="):
        closeFile(fileFd)
        res.status(Http416).send("Range Not Satisfiable")
        return

  if closeConn:
    res.closeConn = true
  let connHeader = if closeConn: "close" else: "keep-alive"

  res.sent = true
  var hdrBuf: array[768, byte]
  var p = 0

  if status == Http200:
    copyMem(addr hdrBuf[p], "HTTP/1.1 200 OK\r\n".cstring, 17); p += 17
  else:
    copyMem(addr hdrBuf[p], "HTTP/1.1 206 Partial Content\r\n".cstring, 30); p += 30

  copyMem(addr hdrBuf[p], "Content-Length: ".cstring, 16); p += 16
  p += writeUint(cast[ptr UncheckedArray[byte]](addr hdrBuf[p]), rangeLen)
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  copyMem(addr hdrBuf[p], "Accept-Ranges: bytes\r\n".cstring, 22); p += 22

  let ext = getFileExt(path)[1..^1]
  let mimeType = if isExtension(ext): getMimeType(ext).get() else: "application/octet-stream"
  copyMem(addr hdrBuf[p], "Content-Type: ".cstring, 14); p += 14
  copyMem(addr hdrBuf[p], mimeType.cstring, mimeType.len); p += mimeType.len
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  let (_, fileName, _) = path.splitFile()
  writeDisposition(cast[ptr UncheckedArray[byte]](addr hdrBuf[0]), fileName, p)

  copyMem(addr hdrBuf[p], "Connection: ".cstring, 12); p += 12
  copyMem(addr hdrBuf[p], connHeader.cstring, connHeader.len); p += connHeader.len
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  copyMem(addr hdrBuf[p], ServerHeader.cstring, ServerHeader.len); p += ServerHeader.len

  for (k, v) in res.headers:
    copyMem(addr hdrBuf[p], k.cstring, k.len); p += k.len
    copyMem(addr hdrBuf[p], ": ".cstring, 2); p += 2
    copyMem(addr hdrBuf[p], v.cstring, v.len); p += v.len
    copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  if status == Http206:
    copyMem(addr hdrBuf[p], "Content-Range: bytes ".cstring, 21); p += 21
    p += writeUint(cast[ptr UncheckedArray[byte]](addr hdrBuf[p]), rangeStart)
    hdrBuf[p] = byte('-'); p += 1
    p += writeUint(cast[ptr UncheckedArray[byte]](addr hdrBuf[p]), rangeStart + rangeLen - 1)
    hdrBuf[p] = byte('/'); p += 1
    p += writeUint(cast[ptr UncheckedArray[byte]](addr hdrBuf[p]), fileSize)
    copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  type Part = tuple[data: ptr UncheckedArray[byte]; len: int]
  var parts: array[6, Part]
  var count = 0
  parts[count] = (cast[ptr UncheckedArray[byte]](addr hdrBuf[0]), p); inc count
  discard res.conn.sendv(parts.toOpenArray(0, count - 1))

  discard seekFile(fileFd, rangeStart)

  var fileOff = rangeStart
  var remain = rangeLen

  while remain > 0:
    let n = sendFileChunk(res.conn.fd, fileFd, fileOff, remain)
    if n > 0:
      continue
    elif n == 0:
      res.conn.sendFileFd = fileFd
      res.conn.sendFileOff = fileOff
      res.conn.sendFileRemain = remain
      res.conn.loop.modify(res.conn.fd.int, {Read, Write})
      return
    else:
      closeFile(fileFd)
      return

  closeFile(fileFd)
  if res.closeConn:
    res.conn.closeAfterDrain()

const
  DefaultChunkSize* = 1_048_576

proc streamFile*(res: Response, path: string, req: HttpRequest;
                 chunkSize = DefaultChunkSize) =
  ## Stream a file for media playback with per-response byte limiting.
  ## Always process Range requests. Caps each response body to `chunkSize`
  ## bytes (default 1 MB) so a seek only transfers one chunk, not the
  ## entire remaining file. Always uses keep-alive.
  ##
  ## No initial (no-Range) request sends 206 with `Content-Range: bytes
  ## 0-(chunkSize-1)/fileSize` — the browser learns the total file size
  ## from the suffix but only receives one chunk.
  if res.sent: return

  let fileFd = openFileRead(path)
  if fileFd < 0:
    res.status(Http404).send("File not found")
    return

  var fileSize = getFileSize(fileFd)
  if fileSize < 0:
    closeFile(fileFd)
    res.status(Http404).send("File not found")
    return

  var rangeStart = 0i64
  var rangeLen = min(chunkSize.int64, fileSize)
  var status = Http206

  let headers = req.getHeaders()
  if headers.hasKey("range"):
    let rangeVal = headers["range"].toLowerAscii()
    let r = parseRange(rangeVal, fileSize)
    if r.ok:
      rangeStart = r.start
      rangeLen = min(r.length, chunkSize.int64)
      status = Http206
    elif rangeVal.startsWith("bytes="):
      closeFile(fileFd)
      res.status(Http416).send("Range Not Satisfiable")
      return

  res.sent = true
  var hdrBuf: array[768, byte]
  var p = 0

  copyMem(addr hdrBuf[p], "HTTP/1.1 206 Partial Content\r\n".cstring, 30); p += 30

  copyMem(addr hdrBuf[p], "Content-Length: ".cstring, 16); p += 16
  p += writeUint(cast[ptr UncheckedArray[byte]](addr hdrBuf[p]), rangeLen)
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  copyMem(addr hdrBuf[p], "Accept-Ranges: bytes\r\n".cstring, 22); p += 22

  let ext = getFileExt(path)[1..^1]
  let mimeType = if isExtension(ext): getMimeType(ext).get() else: "application/octet-stream"
  copyMem(addr hdrBuf[p], "Content-Type: ".cstring, 14); p += 14
  copyMem(addr hdrBuf[p], mimeType.cstring, mimeType.len); p += mimeType.len
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  copyMem(addr hdrBuf[p], "Connection: keep-alive\r\n".cstring, 24); p += 24

  copyMem(addr hdrBuf[p], ServerHeader.cstring, ServerHeader.len); p += ServerHeader.len

  for (k, v) in res.headers:
    copyMem(addr hdrBuf[p], k.cstring, k.len); p += k.len
    copyMem(addr hdrBuf[p], ": ".cstring, 2); p += 2
    copyMem(addr hdrBuf[p], v.cstring, v.len); p += v.len
    copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  let rangeEnd = min(rangeStart + rangeLen - 1, fileSize - 1)
  copyMem(addr hdrBuf[p], "Content-Range: bytes ".cstring, 21); p += 21
  p += writeUint(cast[ptr UncheckedArray[byte]](addr hdrBuf[p]), rangeStart)
  hdrBuf[p] = byte('-'); p += 1
  p += writeUint(cast[ptr UncheckedArray[byte]](addr hdrBuf[p]), rangeEnd)
  hdrBuf[p] = byte('/'); p += 1
  p += writeUint(cast[ptr UncheckedArray[byte]](addr hdrBuf[p]), fileSize)
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  type Part = tuple[data: ptr UncheckedArray[byte]; len: int]
  var parts: array[6, Part]
  var count = 0
  parts[count] = (cast[ptr UncheckedArray[byte]](addr hdrBuf[0]), p); inc count
  discard res.conn.sendv(parts.toOpenArray(0, count - 1))

  discard seekFile(fileFd, rangeStart)

  var fileOff = rangeStart
  var remain = rangeLen

  while remain > 0:
    let n = sendFileChunk(res.conn.fd, fileFd, fileOff, remain)
    if n > 0:
      continue
    elif n == 0:
      res.conn.sendFileFd = fileFd
      res.conn.sendFileOff = fileOff
      res.conn.sendFileRemain = remain
      res.conn.loop.modify(res.conn.fd.int, {Read, Write})
      return
    else:
      closeFile(fileFd)
      return

  closeFile(fileFd)

proc sendError*(res: Response, code: HttpCode, msg: string = "") =
  ## Send an error response and close the connection.
  res.status(code)
  res.header("Content-Type", "text/plain; charset=utf-8")
  res.close()
  res.send(msg)

proc getConn*(res: Response): Connection {.inline.} =
  ## Get the underlying TCP connection. Used by protocol upgrade
  ## handlers (e.g. WebSocket) that need direct access to the socket.
  res.conn

proc markSent*(res: Response) {.inline.} =
  ## Mark this response as sent without writing any bytes.
  ## Used by upgrade handlers that send the response manually.
  res.sent = true

# ── Response pooling ──────────────────────────────────────────────────────────

proc acquireResponse(server: HttpServer, conn: Connection): Response =
  if server.resPool.len > 0:
    result = server.resPool.pop()
    result.conn = conn
    result.headers.setLen(0)
    result.bodyBytes.setLen(0)
    result.sent = false
    result.statusCode = Http200
    result.closeConn = false
  else:
    result = Response(
      conn: conn, sent: false, statusCode: Http200,
      headers: @[], bodyBytes: @[], closeConn: false)

proc releaseResponse(server: HttpServer, res: Response) =
  if server.resPool.len < MaxResPoolSize:
    server.resPool.add(res)

# ── HttpServer lifecycle ─────────────────────────────────────────────────────

proc newHttpServer*(loop: Loop): HttpServer =
  ## Create a new HTTP server.
  HttpServer(
    tcpServer: nil,
    loop:      loop,
    routes:    initTable[HttpMethod, Table[string, Handler]](8),
    fallback:  nil,
    sessions:  initTable[int, Session](64),
    parserPool: @[],
    resPool:   @[],
    keepAliveMs: DefaultKeepAliveMs
  )

proc acquireParser(server: HttpServer): HttpParser =
  if server.parserPool.len > 0:
    result = server.parserPool.pop()
    result.reset()
  else:
    result = newHttpParser()

proc releaseParser(server: HttpServer, parser: HttpParser) =
  if server.parserPool.len < MaxParserPoolSize:
    parser.reset()
    server.parserPool.add(parser)

proc setKeepAliveTimeout*(server: HttpServer, ms: int) =
  ## Set the keep-alive idle timeout in milliseconds. 0 disables it.
  server.keepAliveMs = ms

proc removeSession*(server: HttpServer, fd: int) =
  ## Clean up a connection's session. Public so protocol upgrade
  ## handlers (e.g. WebSocket) can take over a connection.
  if fd in server.sessions:
    releaseParser(server, server.sessions[fd].parser)
    server.sessions.del(fd)

# ── Request dispatch ─────────────────────────────────────────────────────────

proc dispatchRequest(server: HttpServer, conn: Connection,
                     req: HttpRequest) =
  ## Find a matching route and invoke the handler.
  let meth = req.getMethod()
  let path = req.getPath()
  let res = acquireResponse(server, conn)

  # Respect client's "Connection: close" header (fast-scanned during parse)
  if req.getConnectionClose():
    res.closeConn = true

  var matched = false
  if meth in server.routes:
    let handler = server.routes[meth].getOrDefault(path)
    if handler != nil:
      handler(req, res)
      matched = true
  if not matched:
    if server.fallback != nil:
      server.fallback(req, res)
    else:
      res.sendError(Http404, "Not Found")
  releaseResponse(server, res)


proc handleConnectionData(server: HttpServer, conn: Connection,
                          data: openArray[byte]) =
  ## Feed incoming bytes into the per-connection parser.
  ## Supports HTTP/1.1 pipelining: if multiple complete requests arrive
  ## in the same TCP read, all of them are processed in order.
  let fd = conn.fd.int
  if fd notin server.sessions:
    server.sessions[fd] = Session(parser: acquireParser(server))

  server.sessions[fd].parser.feed(data)

  while server.sessions[fd].parser.isComplete():
    let req = server.sessions[fd].parser.getRequest()
    server.dispatchRequest(conn, req)
    if fd notin server.sessions:
      return  # removed by upgrade (e.g. websocketUpgrade)
    server.sessions[fd].parser.resetForNext()
    discard server.sessions[fd].parser.feed(@[])
    if conn.sendFileFd >= 0:
      break

  if server.sessions[fd].parser.isError():
    let errCode = server.sessions[fd].parser.error()
    let res = acquireResponse(server, conn)
    res.sendError(errCode, "Bad Request")
    if fd in server.sessions:
      server.sessions[fd].parser.reset()

# ── Route registration ───────────────────────────────────────────────────────

proc route*(server: HttpServer, meth: HttpMethod, path: string,
            handler: Handler) =
  ## Register a route handler.
  if meth notin server.routes:
    server.routes[meth] = initTable[string, Handler]()
  server.routes[meth][path] = handler

proc get*(server: HttpServer, path: string, handler: Handler) =
  ## Register a GET route handler.
  server.route(HttpGet, path, handler)

proc post*(server: HttpServer, path: string, handler: Handler) =
  ## Register a POST route handler.
  server.route(HttpPost, path, handler)

proc put*(server: HttpServer, path: string, handler: Handler) =
  ## Register a PUT route handler.
  server.route(HttpPut, path, handler)

proc patch*(server: HttpServer, path: string, handler: Handler) =
  ## Register a PATCH route handler.
  server.route(HttpPatch, path, handler)

proc delete*(server: HttpServer, path: string, handler: Handler) =
  ## Register a DELETE route handler.
  server.route(HttpDelete, path, handler)

proc head*(server: HttpServer, path: string, handler: Handler) =
  ## Register a HEAD route handler.
  server.route(HttpHead, path, handler)

proc options*(server: HttpServer, path: string, handler: Handler) =
  ## Register an OPTIONS route handler.
  server.route(HttpOptions, path, handler)

proc notFound*(server: HttpServer, handler: Handler) =
  ## Register a catch-all handler for unmatched routes.
  server.fallback = handler

# ── Listen ───────────────────────────────────────────────────────────────────

proc listen*(server: HttpServer, address: string, port: int) =
  ## Bind and start accepting HTTP connections on a TCP port.
  server.tcpServer = newTcpServer(server.loop,
    onAccept = proc(conn: Connection) =
      # Pre-create session
      server.sessions[conn.fd.int] = Session(parser: acquireParser(server))
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      server.handleConnectionData(conn, data)
    ,
    onClose = proc(conn: Connection) =
      server.removeSession(conn.fd.int)
    ,
  )
  server.tcpServer.listen(address, port)

when not defined(windows):
  proc listenUnix*(server: HttpServer, path: string; mode: int = 0o660) =
    ## Bind and start accepting HTTP connections on a Unix domain socket.
    server.tcpServer = newTcpServer(server.loop,
      onAccept = proc(conn: Connection) =
        server.sessions[conn.fd.int] = Session(parser: acquireParser(server))
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        server.handleConnectionData(conn, data)
      ,
      onClose = proc(conn: Connection) =
        server.removeSession(conn.fd.int)
      ,
    )
    server.tcpServer.listenUnix(path, mode)

proc close*(server: HttpServer) =
  ## Shut down the server.
  if server.tcpServer != nil:
    server.tcpServer.close()
  server.sessions.clear()
  server.parserPool.setLen(0)

proc ensureTcpServer*(server: HttpServer) =
  ## Lazily create the underlying TcpServer (for multi-thread use where
  ## listen() is called before routes are registered).
  if server.tcpServer != nil: return
  server.tcpServer = newTcpServer(server.loop,
    onAccept = proc(conn: Connection) =
      server.sessions[conn.fd.int] = Session(parser: acquireParser(server))
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      server.handleConnectionData(conn, data)
    ,
    onClose = proc(conn: Connection) =
      server.removeSession(conn.fd.int)
  )

proc addConnection*(server: HttpServer, fd: SocketHandle) =
  ## Inject a pre-accepted client fd into this HTTP server's event loop.
  ## Used by multi-threaded acceptors that distribute connections to workers.
  server.ensureTcpServer()
  server.tcpServer.injectFd(fd)

proc getLoop*(server: HttpServer): Loop {.inline.} =
  ## Get the event loop associated with this server.
  server.loop
