# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## A non-blocking HTTP/1.1 server built on top of powpow's TCP primitives.
##
## Combines the TCP transport layer with the incremental HTTP parser.
## Higher-level frameworks implement routing via the `OnRequestCallback`.
##
## ### Usage:
##   ```nim
##   let server = newHttpServer()
##   server.start do (req: HttpRequest, res: HttpResponse):
##     if req.getPath() == "/":
##       res.status(Http200).send("Hello, World!")
##     else:
##       res.sendError(Http404, "Not Found")
##   , Port(9000)
##   ```

import std/[httpcore, tables, options, net, strutils, os, posix]

import ../net/tcp
import ../net/common
import ../loop
import ../types
import ./http

import pkg/[mimedb, multipart]
export Port

# ── Types ────────────────────────────────────────────────────────────────────

type
  HttpResponse* = ref object
    ## Build and send an HTTP response.
    conn:       Connection
    sent:       bool
    statusCode: HttpCode
    headers:    seq[(string, string)]
    bodyBytes:  seq[byte]
    closeConn:  bool           ## If true, send "Connection: close" and shut down

  OnRequestCallback* = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.}
    ## User-provided callback invoked for every parsed HTTP request.
    ## Higher-level frameworks implement routing on top of this.

  ConnHttp* = ref object
    parser: HttpParser
    sessionStreamFile: File
    sessionStreamPath: string

  HttpServer* = ref object
    tcpServer: TcpServer
    loop:      Loop
    handler*:  OnRequestCallback
    connRoots: Table[int, ConnHttp]
    parserPool: seq[HttpParser]
    reqPool:   seq[HttpRequest]
    resPool:   seq[HttpResponse]
    keepAliveMs: int
    maxBodySize*: int64
    maxConnections*: int
    maxPipelineDepth*: int
    readTimeoutMs*: int

const
  DefaultKeepAliveMs* = 5_000
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

# ── HttpResponse ─────────────────────────────────────────────────────────────────

proc newHttpResponse(conn: Connection): HttpResponse =
  HttpResponse(
    conn:       conn,
    sent:       false,
    statusCode: Http200,
    headers:    @[],
    bodyBytes:  @[],
    closeConn:  false,
  )

proc status*(res: HttpResponse, code: HttpCode): HttpResponse {.discardable.} =
  ## Set the HTTP status code.
  res.statusCode = code
  return res

proc header*(res: HttpResponse, key, value: string): HttpResponse {.discardable.} =
  ## Add a response header.
  res.headers.add((key, value))
  return res

proc close*(res: HttpResponse): HttpResponse {.discardable.} =
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

proc send*(res: HttpResponse, body: string = "") =
  if res.sent: return
  res.sent = true
  let connHeader = if res.closeConn: "close" else: "keep-alive"

  var hdrBuf: array[256, byte]
  var p = 0

  copyMem(addr hdrBuf[p], "HTTP/1.1 ".cstring, 9); p += 9
  p += writeUint(cast[ptr UncheckedArray[byte]](addr hdrBuf[p]), res.statusCode.int)
  hdrBuf[p] = byte(' '); p += 1
  let stext = statusText(res.statusCode)
  copyMem(addr hdrBuf[p], stext.cstring, stext.len); p += stext.len
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  copyMem(addr hdrBuf[p], "Content-Length: ".cstring, 16); p += 16
  p += writeUint(cast[ptr UncheckedArray[byte]](addr hdrBuf[p]), body.len)
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  copyMem(addr hdrBuf[p], "Connection: ".cstring, 12); p += 12
  copyMem(addr hdrBuf[p], connHeader.cstring, connHeader.len); p += connHeader.len
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  # Fast path: single write for tiny responses (≤512 bytes, no custom headers)
  let totalLen = p + 2 + body.len
  if totalLen <= 512 and res.headers.len == 0:
    var buf: array[512, byte]
    copyMem(addr buf[0], addr hdrBuf[0], p)
    var pos = p
    copyMem(addr buf[pos], "\r\n".cstring, 2); pos += 2
    if body.len > 0:
      copyMem(addr buf[pos], unsafeAddr body[0], body.len); pos += body.len
    discard sockSend(res.conn.fd, addr buf[0], pos)
  else:
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

proc send*(res: HttpResponse, body: seq[byte]) =
  if res.sent: return
  res.sent = true
  let connHeader = if res.closeConn: "close" else: "keep-alive"

  var hdrBuf: array[256, byte]
  var p = 0

  copyMem(addr hdrBuf[p], "HTTP/1.1 ".cstring, 9); p += 9
  p += writeUint(cast[ptr UncheckedArray[byte]](addr hdrBuf[p]), res.statusCode.int)
  hdrBuf[p] = byte(' '); p += 1
  let stext = statusText(res.statusCode)
  copyMem(addr hdrBuf[p], stext.cstring, stext.len); p += stext.len
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  copyMem(addr hdrBuf[p], "Content-Length: ".cstring, 16); p += 16
  p += writeUint(cast[ptr UncheckedArray[byte]](addr hdrBuf[p]), body.len)
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  copyMem(addr hdrBuf[p], "Connection: ".cstring, 12); p += 12
  copyMem(addr hdrBuf[p], connHeader.cstring, connHeader.len); p += connHeader.len
  copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

  let totalLen = p + 2 + body.len
  if totalLen <= 512 and res.headers.len == 0:
    var buf: array[512, byte]
    copyMem(addr buf[0], addr hdrBuf[0], p)
    var pos = p
    copyMem(addr buf[pos], "\r\n".cstring, 2); pos += 2
    if body.len > 0:
      copyMem(addr buf[pos], addr body[0], body.len); pos += body.len
    discard sockSend(res.conn.fd, addr buf[0], pos)
  else:
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

proc sendFile*(res: HttpResponse, path: string;
               req: HttpRequest = default(HttpRequest);
               closeConn = true,
               contentDisposition = true) =
  ## Send a file for download using zero-copy when possible.
  ## Adds `Content-Disposition: attachment; filename="..."` when `contentDisposition` is true.
  ## Supports HTTP Range requests when `req` is provided.
  ## `closeConn` controls connection lifetime: true (default) closes after
  ## the transfer; false keeps the connection alive.
  {.gcsafe.}:
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

    if contentDisposition:
      let (_, fileName, _) = path.splitFile()
      writeDisposition(cast[ptr UncheckedArray[byte]](addr hdrBuf[0]), fileName, p)

    copyMem(addr hdrBuf[p], "Connection: ".cstring, 12); p += 12
    copyMem(addr hdrBuf[p], connHeader.cstring, connHeader.len); p += connHeader.len
    copyMem(addr hdrBuf[p], "\r\n".cstring, 2); p += 2

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

#
# Forward declarations
#
proc listen*(server: HttpServer, address: string, port: int)
proc close*(server: HttpServer)

proc streamFile*(res: HttpResponse, path: string, req: HttpRequest;
                 chunkSize = DefaultChunkSize) {.gcsafe.} =
  ## Stream a file for media playback with per-response byte limiting.
  ## Always process Range requests. Caps each response body to `chunkSize`
  ## bytes (default 1 MB) so a seek only transfers one chunk, not the
  ## entire remaining file. Always uses keep-alive.
  ##
  ## No initial (no-Range) request sends 206 with `Content-Range: bytes
  ## 0-(chunkSize-1)/fileSize` — the browser learns the total file size
  ## from the suffix but only receives one chunk.
  {.gcsafe.}:
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

proc sendError*(res: HttpResponse, code: HttpCode, msg: string = "") =
  ## Send an error response and close the connection.
  res.status(code)
  res.header("Content-Type", "text/plain; charset=utf-8")
  res.close()
  res.send(msg)

proc getConn*(res: HttpResponse): Connection {.inline.} =
  ## Get the underlying TCP connection. Used by protocol upgrade
  ## handlers (e.g. WebSocket) that need direct access to the socket.
  res.conn

proc markSent*(res: HttpResponse) {.inline.} =
  ## Mark this response as sent without writing any bytes.
  ## Used by upgrade handlers that send the response manually.
  res.sent = true

# ── HttpResponse pooling ──────────────────────────────────────────────────────────

proc acquireHttpResponse(server: HttpServer, conn: Connection): HttpResponse =
  if server.resPool.len > 0:
    result = server.resPool.pop()
    result.conn = conn
    result.headers.setLen(0)
    result.bodyBytes.setLen(0)
    result.sent = false
    result.statusCode = Http200
    result.closeConn = false
  else:
    result = HttpResponse(
      conn: conn, sent: false, statusCode: Http200,
      headers: @[], bodyBytes: @[], closeConn: false)

proc releaseHttpResponse(server: HttpServer, res: HttpResponse) =
  if server.resPool.len < MaxResPoolSize:
    server.resPool.add(res)

proc acquireRequest(server: HttpServer, p: HttpParser): HttpRequest =
  if server.reqPool.len > 0:
    result = server.reqPool.pop()
    result.parser = p
    result.httpMethod = p.methodCache
    result.urlVal.setLen(0)
    result.headersReady = false
    result.bodyReady = false
  else:
    result = HttpRequest(parser: p, httpMethod: p.methodCache)

proc releaseRequest(server: HttpServer, req: HttpRequest) =
  req.streamPath.setLen(0)
  req.streamer = nil
  req.urlVal.setLen(0)
  req.headersReady = false
  req.bodyReady = false
  server.reqPool.add(req)

# ── HttpServer lifecycle ─────────────────────────────────────────────────────

proc populatePools*(server: HttpServer; poolSize = 256)

proc newHttpServer*(loop: Loop; populate: bool = false): HttpServer =
  let srv = HttpServer(
    tcpServer: nil,
    loop:      loop,
    handler:   nil,
    connRoots: initTable[int, ConnHttp](64),
    parserPool: @[],
    reqPool:   @[],
    resPool:   @[],
    keepAliveMs: DefaultKeepAliveMs,
    maxBodySize: 0,
    maxConnections: 0,
    maxPipelineDepth: 0,
    readTimeoutMs: 0
  )
  if populate:
    srv.populatePools()
  srv

proc newHttpServer*(populate: bool = false): HttpServer =
  var eventLoop = newLoop()
  newHttpServer(eventLoop, populate)

proc start*(server: HttpServer, handler: OnRequestCallback, port: Port) =
  server.handler = handler
  server.listen("0.0.0.0", port.int)
  server.loop.run()

proc stop*(server: HttpServer) =
  ## Stop the HTTP server and close all connections
  server.close()
  server.loop.close()

proc acquireParser(server: HttpServer): HttpParser =
  if server.parserPool.len > 0:
    result = server.parserPool.pop()
    result.reset()
  else:
    result = newHttpParser()
  result.maxBodySize = server.maxBodySize

proc releaseParser(server: HttpServer, parser: HttpParser) =
  if server.parserPool.len < MaxParserPoolSize:
    parser.reset()
    server.parserPool.add(parser)

proc setKeepAliveTimeout*(server: HttpServer, ms: int) =
  ## Set the keep-alive idle timeout in milliseconds. 0 disables it.
  server.keepAliveMs = ms

proc removeSession*(server: HttpServer, conn: Connection) =
  let ctx = cast[ConnHttp](conn.data)
  if ctx == nil: return
  server.connRoots.del(conn.fd.int)
  if ctx.sessionStreamPath.len > 0:
    ctx.sessionStreamFile.close()
    removeFile(ctx.sessionStreamPath)
    ctx.sessionStreamPath = ""
  releaseParser(server, ctx.parser)
  conn.data = nil

# ── Request dispatch ─────────────────────────────────────────────────────────

proc dispatchRequest(server: HttpServer, conn: Connection,
                     req: HttpRequest) =
  let res = acquireHttpResponse(server, conn)
  if req.getConnectionClose():
    res.closeConn = true
  if server.handler != nil:
    server.handler(req, res)
  else:
    res.sendError(Http500, "No handler configured")
  releaseHttpResponse(server, res)


proc handleConnectionData(server: HttpServer, conn: Connection,
                          data: openArray[byte]) =
  ## Feed incoming bytes into the per-connection parser.
  ## Supports HTTP/1.1 pipelining: if multiple complete requests arrive
  ## in the same TCP read, all of them are processed in order.
  ## Multipart/form-data is NOT auto-streamed — handlers must call
  ## `req.getMultipart()` to process it explicitly.
  let ctx = if conn.data != nil: cast[ConnHttp](conn.data)
            else:
              let c = ConnHttp(parser: acquireParser(server))
              conn.data = cast[pointer](c)
              server.connRoots[conn.fd.int] = c
              c
  let p = ctx.parser
  p.feed(data)

  var pipelineCount = 0
  while p.isComplete():
    if server.maxPipelineDepth > 0 and pipelineCount >= server.maxPipelineDepth:
      break
    inc pipelineCount
    let req = server.acquireRequest(p)
    if ctx.sessionStreamPath.len > 0:
      req.streamPath = ctx.sessionStreamPath
      ctx.sessionStreamPath = ""
    server.dispatchRequest(conn, req)
    releaseRequest(server, req)
    if conn.data == nil:
      return
    ctx.parser.resetForNext()
    discard p.feed(@[])
    if conn.sendFileFd >= 0:
      break

  if p.isError():
    if ctx.sessionStreamPath.len > 0:
      ctx.sessionStreamFile.close()
      removeFile(ctx.sessionStreamPath)
      ctx.sessionStreamPath = ""
    p.onBodyData = nil
    let errCode = p.error()
    let res = acquireHttpResponse(server, conn)
    res.sendError(errCode, "Bad Request")
    ctx.parser.reset()

# ── Listen ───────────────────────────────────────────────────────────────────

proc listen*(server: HttpServer, address: string, port: int) =
  server.tcpServer = newTcpServer(server.loop,
    onData = proc(conn: Connection, data: openArray[byte]) =
      server.handleConnectionData(conn, data)
    ,
    onClose = proc(conn: Connection) =
      server.removeSession(conn)
    ,
  )
  server.tcpServer.maxConnections = server.maxConnections
  server.tcpServer.listen(address, port)

when not defined(windows):
  proc listenUnix*(server: HttpServer, path: string; mode: int = 0o660) =
    server.tcpServer = newTcpServer(server.loop,
      onData = proc(conn: Connection, data: openArray[byte]) =
        server.handleConnectionData(conn, data)
      ,
      onClose = proc(conn: Connection) =
        server.removeSession(conn)
      ,
    )
    server.tcpServer.listenUnix(path, mode)

proc close*(server: HttpServer) =
  if server.tcpServer != nil:
    server.tcpServer.close()
  server.connRoots.clear()
  server.parserPool.setLen(0)

proc ensureTcpServer*(server: HttpServer) =
  if server.tcpServer != nil: return
  server.tcpServer = newTcpServer(server.loop,
    onData = proc(conn: Connection, data: openArray[byte]) =
      server.handleConnectionData(conn, data)
    ,
    onClose = proc(conn: Connection) =
      server.removeSession(conn)
  )

proc populatePools*(server: HttpServer; poolSize = 256) =
  ## Pre-allocate parsers, responses, connections, and buffers to
  ## eliminate all allocations on the request hot path.
  if server.tcpServer == nil:
    server.ensureTcpServer()
  for i in 0 ..< poolSize:
    if server.parserPool.len < MaxParserPoolSize:
      server.parserPool.add(newHttpParser())
    if server.resPool.len < MaxResPoolSize:
      server.resPool.add(HttpResponse(
        conn: nil, sent: false, statusCode: Http200,
        headers: @[], bodyBytes: @[], closeConn: false))
    if server.tcpServer.connPool.len < MaxConnPoolSize:
      var buf = cast[ptr UncheckedArray[byte]](allocShared(DefaultBufSize))
      if server.loop.bufPool.len < MaxBufPoolSize:
        server.loop.bufPool.add(buf)
      server.tcpServer.connPool.add(newConnection(
        SocketHandle(-1), server.loop, server.tcpServer, buf, DefaultBufSize))

proc addConnection*(server: HttpServer, fd: SocketHandle) =
  ## Inject a pre-accepted client fd into this HTTP server's event loop.
  ## Used by multi-threaded acceptors that distribute connections to workers.
  server.ensureTcpServer()
  server.tcpServer.injectFd(fd)

proc getLoop*(server: HttpServer): Loop {.inline.} =
  ## Get the event loop associated with this server.
  server.loop

proc serveStatic*(res: HttpResponse, req: HttpRequest,
                  urlPrefix: string, fsRoot: string,
                  indexFiles: seq[string] = @["index.html", "index.htm"]): bool =
  ## Serve static files from `fsRoot` for requests whose path starts with `urlPrefix`.
  ## Path traversal protection: rejects paths containing ".." or "~".
  ## Returns true if the file was served, false if not found (caller should send 404).
  ## Zero-copy: uses `sendFile` internally, no body buffering.
  let path = req.getPath()
  if not path.startsWith(urlPrefix):
    return false
  let relPath = path[urlPrefix.len .. ^1]
  if relPath.contains("..") or relPath.contains("~") or relPath.len == 0 or relPath[0] == '/':
    res.status(Http403).header("Content-Type", "text/plain; charset=utf-8").send("Forbidden")
    return true
  let fullPath = fsRoot / relPath
  if dirExists(fullPath):
    for index in indexFiles:
      let indexPath = fullPath / index
      if fileExists(indexPath):
        res.sendFile(indexPath, req, closeConn = false, contentDisposition = false)
        return true
    return false
  if not fileExists(fullPath):
    return false
  res.sendFile(fullPath, req, closeConn = false, contentDisposition = false)
  return true
