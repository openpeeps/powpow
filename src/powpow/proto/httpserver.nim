# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
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

import std/httpcore except HttpMethod
import std/[tables, options, net, strutils, os, times, oids]

import ../net/tcp
import ../net/tls
import ../net/common
import ../loop
import ../types
import ./http

when defined(windows):
  import ./winpath

import pkg/[mimedb, multipart]
export Port

# ── Types ────────────────────────────────────────────────────────────────────

type
  HttpResponse* = ref object
    ## Build and send an HTTP response.
    conn:       Connection
    server*:    HttpServer   ## owning server (set on acquire) — used by
      ## `websocketUpgrade` to detach the connection from the HTTP session
      ## tracking / timeout sweep when the caller omits the `server` argument
    statusCode: uint16
    sent:       bool
    closeConn:  bool           ## If true, send "Connection: close" and shut down
    headers:    seq[(string, string)]
    bodyBytes:  seq[byte]

  OnRequestCallback* = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.}
    ## User-provided callback invoked for every parsed HTTP request.
    ## Higher-level frameworks implement routing on top of this.

  ConnHttp* = ref object
    parser: HttpParser
    sessionStreamFile: File
    sessionStreamPath: string
    streamer: MultipartStreamerRef
    conn: Connection            ## back-reference used by the timeout sweep
    fd: int                     ## key used in connRoots (conn.fd is -1 after close)
    inRoots: bool               ## true once promoted from pendingConns to connRoots
    pendingIdx: int             ## index in pendingConns while not promoted (-1 after)
    lastActive: int64            ## monoMs of the last data/activity
    idleAfter: int64             ## monoMs when the last request completed (idle)

  HttpServer* = ref object
    tcpServers*: seq[TcpServer]
    loop:      Loop
    handler*:  OnRequestCallback
    sslCtx*:   tls.SslContext
    connRoots*: Table[int, ConnHttp]
    pendingConns*: seq[ConnHttp]  ## Sessions before their first completed
      ## request (never hashed): pure append + swap-remove. A `Connection:
      ## close` connection lives and dies here without ever touching
      ## `connRoots`, and the sweep still applies readTimeoutMs to it.
    parserPool: seq[HttpParser]
    reqPool:   seq[HttpRequest]
    resPool:   seq[HttpResponse]
    connHttpPool*: seq[ConnHttp]  ## Idle per-connection sessions (HTTP/1.1 only)
    wsPool:    seq[ref RootObj]   ## Idle WsConnection refs recycled by websocketUpgrade
      ## Typed as `ref RootObj` (not `pointer`) so ARC-family memory managers
      ## retain the pooled WsConnection — a raw pointer does not hold a ref, so
      ## a released ws could be freed while still in the pool and crash on reuse.
    sweepStale: seq[ConnHttp]  ## Scratch buffer reused by the timeout sweep so
      ## the periodic pass performs no per-sweep allocation.
    keepAliveMs: int
    maxBodySize*: int64
    maxStreamBodySize*: int64
      ## Operator-configurable hard cap for streamed/chunked/multipart bodies
      ## when maxBodySize == 0 (0 = use MaxStreamBodySize). Lets an operator
      ## lower the 512 MB per-connection backstop without changing code.
    minStreamBodySize*: int64
      ## Bodies at or above this size are auto-streamed to a temp file when
      ## they arrive split across reads; smaller bodies are buffered so
      ## `req.getBodyString()`/`getBody()` work (0 = use MinStreamBodySize,
      ## the 64 KB default). Streaming exists to keep memory bounded for large
      ## uploads; buffering small bodies avoids breaking getBodyString when the
      ## headers and body arrive in separate TCP segments (common on Windows).
    maxFileSize*: int64
      ## Per-file upload cap for multipart bodies (0 = fall back to
      ## maxBodySize's effective cap). Bounds disk usage of a single part
      ## independently of the total body size.
    maxFieldSize*: int64
      ## Per-text-field cap for multipart bodies (0 = fall back to
      ## maxBodySize's effective cap). Bounds per-field RAM usage.
    maxConnections*: int
    maxPipelineDepth*: int
    readTimeoutMs*: int
    wsIdleTimeoutMs*: int
      ## Post-upgrade WebSocket idle timeout (ms, 0 = disabled). Applied when a
      ## route upgrades a connection via `websocketUpgrade`; closes upgraded
      ## connections that send no frames within the window.
    timeoutSweepMs*: int
      ## How often the lazy timeout sweep runs (ms). The sweep closes
      ## connections that exceed readTimeoutMs (mid-request) or keepAliveMs
      ## (idle) with one periodic pass over active connections — avoiding a
      ## per-request timer add/cancel on the hot path.
    sweepTimer: TimerId

const
  DefaultKeepAliveMs* = 5_000
  MaxParserPoolSize {.intdefine.} = 2048
    ## Idle HTTP parsers recycled across connections. Override at compile time
    ## (`-d:MaxParserPoolSize=4096`) when serving more concurrent connections
    ## than the default holds; see the sizing guide in docs/contents/performance.md.
  MaxResPoolSize {.intdefine.} = 4048
    ## Idle HTTP responses recycled per request (same tuning as above).
  MaxReqPoolSize {.intdefine.} = 2048
    ## Idle HTTP requests recycled per request (same tuning as above).
  MaxConnHttpPoolSize {.intdefine.} = 2048
    ## Idle per-connection HTTP sessions recycled across connections. Reusing
    ## the object removes the last per-connection allocation on the hot path
    ## (parsers, requests and responses were already pooled).
  MaxWsPoolSize* = 2048
    ## Idle WebSocket connections recycled by websocketUpgrade. Reusing the
    ## object keeps its 64KB frame-parser payload and assembly buffer alive, so
    ## WS connection churn does not re-allocate them.

var httpDateCache {.threadvar.}: string
var httpDateSec {.threadvar.}: int64

proc cachedHttpDate(): string {.inline.} =
  ## RFC 7231 IMF-fixdate ("Sun, 06 Nov 1994 08:49:37 GMT"), cached once per
  ## second per thread so the response hot path never re-formats it.
  ## Reads the wall clock sampled once per event-loop iteration instead of a
  ## per-request `clock_gettime` — at most one iteration stale, far below the
  ## header's 1-second resolution. Falls back to a direct sample outside a
  ## running loop (unit tests).
  let sec = if pollWallSec != 0: pollWallSec else: getTime().toUnix()
  if sec != httpDateSec:
    httpDateSec = sec
    let dt = fromUnix(sec).utc()
    const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    httpDateCache = days[dt.weekday.ord] & ", " &
                    align($dt.monthday, 2, '0') & " " &
                    months[dt.month.ord - 1] & " " & $dt.year & " " &
                    align($dt.hour, 2, '0') & ":" &
                    align($dt.minute, 2, '0') & ":" &
                    align($dt.second, 2, '0') & " GMT"
  httpDateCache


func getFileExt*(path: string): string {.inline.} =
  ## Return the lowercased file extension without the leading dot
  ## (e.g. `png`), or "" when the path has no extension.
  ## Single reverse scan: no `splitFile` temporaries, one result alloc.
  ## A dot that opens the file name (`.gitignore`) is not an extension.
  var i = path.len - 1
  while i >= 0:
    let c = path[i]
    when defined(windows):
      if c == '/' or c == '\\': break
    else:
      if c == '/': break
    if c == '.':
      if i == path.len - 1 or i == 0: return ""
      let prev = path[i - 1]
      when defined(windows):
        if prev == '/' or prev == '\\': return ""
      else:
        if prev == '/': return ""
      result = newString(path.len - i - 1)
      for k in 0 ..< result.len:
        var ch = path[i + 1 + k]
        if ch >= 'A' and ch <= 'Z': ch = chr(ord(ch) + (ord('a') - ord('A')))
        result[k] = ch
      return
    dec i
  ""

func isBytesUnit*(s: string): bool {.inline.} =
  ## ASCII case-insensitive "bytes=" prefix check without allocating
  ## (replaces `s.toLowerAscii().startsWith("bytes=")` on hot paths).
  if s.len < 6: return false
  const unit = "bytes="
  for i in 0 ..< 6:
    var a = s[i]
    if a >= 'A' and a <= 'Z': a = chr(ord(a) + (ord('a') - ord('A')))
    if a != unit[i]: return false
  true

func parseRange*(rangeHeader: string; fileSize: int64): tuple[ok: bool; start, length: int64] =
  if not isBytesUnit(rangeHeader): return (false, 0, 0)
  if fileSize <= 0: return (false, 0, 0)

  var i = 6
  let hlen = rangeHeader.len

  var dashPos = i
  while dashPos < hlen and rangeHeader[dashPos] != '-':
    inc dashPos
  if dashPos >= hlen: return (false, 0, 0)

  var rangeStart = 0i64
  var hasStart = false
  if dashPos > i:
    hasStart = true
    var j = i
    while j < dashPos:
      let c = rangeHeader[j]
      if c < '0' or c > '9': return (false, 0, 0)
      let digit = int64(ord(c) - ord('0'))
      if rangeStart > high(int64) div 10: return (false, 0, 0)
      rangeStart = rangeStart * 10 + digit
      inc j

  var rangeEnd = fileSize - 1
  var hasEnd = false
  i = dashPos + 1
  if i < hlen:
    hasEnd = true
    var num = 0i64
    while i < hlen:
      let c = rangeHeader[i]
      if c < '0' or c > '9': break
      let digit = int64(ord(c) - ord('0'))
      if num > high(int64) div 10: return (false, 0, 0)
      num = num * 10 + digit
      inc i
    rangeEnd = num
    # Strict: after the end number only trailing OWS is allowed. Trailing
    # garbage (`bytes=0-5x`) or a second range (`bytes=0-1,3-4`) must be
    # rejected, not silently truncated (two servers would disagree on the
    # range).
    while i < hlen and (rangeHeader[i] == ' ' or rangeHeader[i] == '\t'):
      inc i
    if i < hlen: return (false, 0, 0)

  if hasStart and hasEnd:
    if rangeStart > rangeEnd or rangeStart < 0: return (false, 0, 0)
    if rangeStart >= fileSize: return (false, 0, 0)
    if rangeEnd >= fileSize: rangeEnd = fileSize - 1
  elif hasStart:
    if rangeStart < 0 or rangeStart >= fileSize: return (false, 0, 0)
    rangeEnd = fileSize - 1
  elif hasEnd:
    let suffixLen = rangeEnd
    if suffixLen <= 0: return (false, 0, 0)
    if suffixLen >= fileSize: rangeStart = 0
    else: rangeStart = fileSize - suffixLen
    rangeEnd = fileSize - 1
  else:
    return (false, 0, 0)

  result = (true, rangeStart, rangeEnd - rangeStart + 1)

# ── HttpResponse ─────────────────────────────────────────────────────────────────

proc status*(res: HttpResponse, code: HttpCode): HttpResponse {.inline, discardable.} =
  res.statusCode = uint16(code)
  return res

proc header*(res: HttpResponse, key, value: string): HttpResponse {.inline, discardable.} =
  res.headers.add((key, value))
  return res

proc close*(res: HttpResponse): HttpResponse {.inline, discardable.} =
  res.closeConn = true
  return res

proc ktlsTxActive*(res: HttpResponse): bool {.inline.} =
  ## True when this response's connection has kTLS TX offload engaged (the
  ## kernel encrypts the transmit path, so `serveFile` uses zero-copy
  ## `sendfile(2)` even over TLS). See `enableKtls` (net/tls).
  res.conn.ktlsTxActive()

func statusText(code: HttpCode): string {.inline.} =
  ## Return the HTTP reason phrase for a status code.
  ## Returns a string literal (no heap allocation).
  case code.int
  of 100: "Continue"
  of 101: "Switching Protocols"
  of 102: "Processing"
  of 200: "OK"
  of 201: "Created"
  of 202: "Accepted"
  of 204: "No Content"
  of 206: "Partial Content"
  of 207: "Multi-Status"
  of 208: "Already Reported"
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
  of 422: "Unprocessable Entity"
  of 423: "Locked"
  of 424: "Failed Dependency"
  of 429: "Too Many Requests"
  of 431: "Request Header Fields Too Large"
  of 500: "Internal Server Error"
  of 501: "Not Implemented"
  of 507: "Insufficient Storage"
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
  var digits {.noinit.}: array[20, byte]
  var ndigits = 0
  while tmp > 0:
    digits[ndigits] = byte(ord('0') + tmp mod 10)
    inc ndigits
    tmp = tmp div 10
  for i in 0 ..< ndigits:
    buf[i] = digits[ndigits - 1 - i]
  return ndigits

{.push gcsafe.}

const
  FastSingleWriteCap = 1024
    ## Max total response bytes for the single-`send()` fast path (status +
    ## fixed headers + custom headers + blank line + body). The `/` demo
    ## response (~540B with its Content-Type header) fits, so the hot path
    ## issues one `send()` instead of `writev()` over a 7-part iovec.

template sendResponse(res: HttpResponse, bodyLen: int, bodyPtr: pointer) =
  ## Shared response serializer for `send(string)` / `send(seq[byte])`.
  ## Emits byte-identical output on both paths; only the transport differs
  ## (one coalesced `send()` when the response fits the stack buffer,
  ## otherwise the scatter `sendv()` as before).
  ##
  ## Single-pass build: the fixed headers are emitted directly into the
  ## final stack buffer and custom headers appended in the same loop that
  ## bounds-checks them — no intermediate header buffer, no second copy,
  ## no pre-count pass over `res.headers`.
  res.sent = true
  let connHeader = if res.closeConn: "close" else: "keep-alive"

  var buf {.noinit.}: array[FastSingleWriteCap, byte]
  var p = 0

  copyMem(addr buf[p], "HTTP/1.1 ".cstring, 9); p += 9
  p += writeUint(cast[ptr UncheckedArray[byte]](addr buf[p]), res.statusCode.int)
  buf[p] = byte(' '); p += 1
  let stext = statusText(HttpCode(res.statusCode))
  copyMem(addr buf[p], stext.cstring, stext.len); p += stext.len
  copyMem(addr buf[p], "\r\n".cstring, 2); p += 2

  copyMem(addr buf[p], "Date: ".cstring, 6); p += 6
  let httpDate = cachedHttpDate()
  copyMem(addr buf[p], httpDate.cstring, httpDate.len); p += httpDate.len
  copyMem(addr buf[p], "\r\n".cstring, 2); p += 2

  copyMem(addr buf[p], "Content-Length: ".cstring, 16); p += 16
  p += writeUint(cast[ptr UncheckedArray[byte]](addr buf[p]), bodyLen)
  copyMem(addr buf[p], "\r\n".cstring, 2); p += 2

  copyMem(addr buf[p], "Connection: ".cstring, 12); p += 12
  copyMem(addr buf[p], connHeader.cstring, connHeader.len); p += connHeader.len
  copyMem(addr buf[p], "\r\n".cstring, 2); p += 2
  # Fixed part is <= ~144 bytes (longest reason phrase is 30 chars), so it
  # always fits the 1024-byte buffer; only custom headers + body can overflow.
  let fixedEnd = p

  let tailReserve = 2 + bodyLen  # final CRLF + body
  # Account for the tail up front: with zero custom headers the loop below
  # never runs, so starting from `true` would wrongly take the fast path and
  # overflow the 1024-byte stack buffer with a large body.
  var fit = p + tailReserve <= FastSingleWriteCap
  for (k, v) in res.headers:
    # Reserve space for this header plus everything that still follows it,
    # so a successful loop guarantees the tail fits without re-checking.
    if p + k.len + v.len + 4 + tailReserve > FastSingleWriteCap:
      fit = false
      break
    copyMem(addr buf[p], k.cstring, k.len); p += k.len
    copyMem(addr buf[p], ": ".cstring, 2); p += 2
    copyMem(addr buf[p], v.cstring, v.len); p += v.len
    copyMem(addr buf[p], "\r\n".cstring, 2); p += 2

  if fit:
    # Fast path: everything coalesced in one stack buffer, one send().
    copyMem(addr buf[p], "\r\n".cstring, 2); p += 2
    if bodyLen > 0:
      copyMem(addr buf[p], bodyPtr, bodyLen); p += bodyLen
    discard res.conn.send(buf.toOpenArray(0, p - 1))
  else:
    type Part = tuple[data: ptr UncheckedArray[byte], len: int]
    const MaxParts = 150
    let numParts = 1 + res.headers.len * 4 + 1 + (if bodyLen > 0: 1 else: 0)

    template scatterWrite(parts: var openArray[Part], count: var int) =
      # First part is the fixed headers only (custom headers that fit were
      # appended past fixedEnd but are re-emitted below, so stop before them).
      parts[count] = (cast[ptr UncheckedArray[byte]](addr buf[0]), fixedEnd); inc count
      for (k, v) in res.headers:
        parts[count] = (cast[ptr UncheckedArray[byte]](k.cstring), k.len); inc count
        parts[count] = (cast[ptr UncheckedArray[byte]](": ".cstring), 2); inc count
        parts[count] = (cast[ptr UncheckedArray[byte]](v.cstring), v.len); inc count
        parts[count] = (cast[ptr UncheckedArray[byte]]("\r\n".cstring), 2); inc count
      parts[count] = (cast[ptr UncheckedArray[byte]]("\r\n".cstring), 2); inc count
      if bodyLen > 0:
        parts[count] = (cast[ptr UncheckedArray[byte]](bodyPtr), bodyLen); inc count

    if numParts <= MaxParts:
      var parts {.noinit.}: array[MaxParts, Part]
      var count = 0
      scatterWrite(parts, count)
      discard res.conn.sendv(parts.toOpenArray(0, count - 1))
    else:
      var parts = newSeq[Part](numParts)
      var count = 0
      scatterWrite(parts, count)
      discard res.conn.sendv(parts.toOpenArray(0, count - 1))

  if res.closeConn:
    res.conn.closeAfterSend()

proc send*(res: HttpResponse, body: string = "") =
  if res.sent: return
  if body.len > 0:
    sendResponse(res, body.len, unsafeAddr body[0])
  else:
    sendResponse(res, 0, nil)

proc send*(res: HttpResponse, body: seq[byte]) =
  if res.sent: return
  if body.len > 0:
    sendResponse(res, body.len, unsafeAddr body[0])
  else:
    sendResponse(res, 0, nil)

{.pop.}
proc writeDisposition*(buf: ptr UncheckedArray[byte]; name: string; p: var int) {.inline.} =
  copyMem(addr buf[p], "Content-Disposition: attachment; filename=\"".cstring, 43); p += 43
  copyMem(addr buf[p], name.cstring, name.len); p += name.len
  copyMem(addr buf[p], "\"\r\n".cstring, 3); p += 3

template hdrEnsure(buf: var seq[byte]; p, need: int) =
  ## Grow `buf` so that p + need bytes fit (response headers may be driven by
  ## attacker-controlled data — e.g. long filenames or custom headers — so a
  ## fixed-size stack buffer would overflow; copyMem bypasses Nim's checks).
  if p + need > buf.len:
    buf.setLen(max(p + need, buf.len * 2))

template hdrAdd(buf: var seq[byte]; p: var int; src: string; n: int) =
  hdrEnsure(buf, p, n)
  copyMem(addr buf[p], src.cstring, n)
  p += n

template hdrAdd(buf: var seq[byte]; p: var int; s: string) =
  hdrAdd(buf, p, s, s.len)

template hdrDate(buf: var seq[byte]; p: var int) =
  hdrAdd(buf, p, "Date: ")
  hdrAdd(buf, p, cachedHttpDate())
  hdrAdd(buf, p, "\r\n")

template hdrByte(buf: var seq[byte]; p: var int; b: byte) =
  hdrEnsure(buf, p, 1)
  buf[p] = b
  p += 1

template hdrUint(buf: var seq[byte]; p: var int; val: int64) =
  hdrEnsure(buf, p, 20)
  p += writeUint(cast[ptr UncheckedArray[byte]](addr buf[p]), val)

proc sendFile*(res: HttpResponse, path: string;
               req: HttpRequest = default(HttpRequest);
               closeConn = true,
               contentDisposition = true,
               skipRange = false) =
  ## Send a file for download using zero-copy when possible.
  ## Adds `Content-Disposition: attachment; filename="..."` when `contentDisposition` is true.
  ## Supports HTTP Range requests when `req` is provided.
  ## `closeConn` controls connection lifetime: true (default) closes after
  ## the transfer; false keeps the connection alive.
  ## `skipRange` bypasses Range header parsing (used when upper layer
  ## already decided Range should not be honored via If-Range).
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

    if not skipRange and req != default(HttpRequest):
      # Zero-alloc range lookup: no header-table materialization, and
      # parseRange folds case inline (no toLowerAscii copy).
      let rangeVal = req.getHeaderValue("range")
      if rangeVal.len > 0:
        let r = parseRange(rangeVal, fileSize)
        if r.ok:
          rangeStart = r.start
          rangeLen = r.length
          status = Http206
        elif rangeVal.isBytesUnit():
          closeFile(fileFd)
          res.status(Http416).send("Range Not Satisfiable")
          return

    if closeConn:
      res.closeConn = true
    # Honor a close requested by the dispatcher (client sent
    # `Connection: close`) even when this call passes closeConn = false
    # (e.g. via serveFile): the header must match the actual lifetime,
    # otherwise a keep-alive header is followed by a close.
    let connHeader = if res.closeConn: "close" else: "keep-alive"

    res.sent = true
    var hdrBuf = res.bodyBytes
    var p = 0

    if status == Http200:
      hdrAdd(hdrBuf, p, "HTTP/1.1 200 OK\r\n", 17)
    else:
      hdrAdd(hdrBuf, p, "HTTP/1.1 206 Partial Content\r\n", 30)

    hdrDate(hdrBuf, p)

    hdrAdd(hdrBuf, p, "Content-Length: ", 16)
    hdrUint(hdrBuf, p, rangeLen)
    hdrAdd(hdrBuf, p, "\r\n", 2)

    hdrAdd(hdrBuf, p, "Accept-Ranges: bytes\r\n", 22)

    let ext = getFileExt(path)
    let mimeType = if isExtension(ext): getMimeType(ext).get() else: "application/octet-stream"
    hdrAdd(hdrBuf, p, "Content-Type: ", 14)
    hdrAdd(hdrBuf, p, mimeType)
    hdrAdd(hdrBuf, p, "\r\n", 2)

    if contentDisposition:
      let (_, fileName, _) = path.splitFile()
      hdrEnsure(hdrBuf, p, 43 + fileName.len + 3)
      writeDisposition(cast[ptr UncheckedArray[byte]](addr hdrBuf[0]), fileName, p)

    hdrAdd(hdrBuf, p, "Connection: ", 12)
    hdrAdd(hdrBuf, p, connHeader)
    hdrAdd(hdrBuf, p, "\r\n", 2)

    for (k, v) in res.headers:
      hdrAdd(hdrBuf, p, k)
      hdrAdd(hdrBuf, p, ": ", 2)
      hdrAdd(hdrBuf, p, v)
      hdrAdd(hdrBuf, p, "\r\n", 2)

    if status == Http206:
      hdrAdd(hdrBuf, p, "Content-Range: bytes ", 21)
      hdrUint(hdrBuf, p, rangeStart)
      hdrByte(hdrBuf, p, byte('-'))
      hdrUint(hdrBuf, p, rangeStart + rangeLen - 1)
      hdrByte(hdrBuf, p, byte('/'))
      hdrUint(hdrBuf, p, fileSize)
      hdrAdd(hdrBuf, p, "\r\n", 2)

    hdrAdd(hdrBuf, p, "\r\n", 2)

    type Part = tuple[data: ptr UncheckedArray[byte]; len: int]
    var parts {.noinit.}: array[6, Part]
    var count = 0
    parts[count] = (cast[ptr UncheckedArray[byte]](addr hdrBuf[0]), p); inc count
    discard res.conn.sendv(parts.toOpenArray(0, count - 1))

    discard seekFile(fileFd, rangeStart)

    if res.conn.isTlsActive() and not res.conn.ktlsTxActive():
      # No zero-copy sendfile over userspace TLS: read the file and send via
      # SSL_write. With kTLS TX offload the kernel frames the TLS records
      # itself, so the plain sendfile path below is safe to use instead.
      # Reuse the pooled res.bodyBytes as the chunk buffer.
      const TlsChunk = 65536
      res.bodyBytes.setLen(TlsChunk)
      var remain = rangeLen
      while remain > 0:
        let toRead = if remain > TlsChunk: TlsChunk else: int(remain)
        let n = readFile(fileFd, cast[ptr UncheckedArray[byte]](addr res.bodyBytes[0]), toRead)
        if n <= 0: break
        discard res.conn.send(res.bodyBytes.toOpenArray(0, int(n) - 1))
        remain -= n
      closeFile(fileFd)
      if res.closeConn:
        res.conn.closeAfterDrain()
      return

    var fileOff = rangeStart
    var remain = rangeLen

    when iouEnabled:
      # io_uring writes are fully asynchronous: the header SEND op above is still
      # in flight, so a synchronous sendfile() here would put file bytes on the
      # wire BEFORE the response headers (clients see HTTP/0.9 garbage). Hand the
      # transfer to the op-driven pump, which waits for the headers to drain
      # first, then streams the file via READ + SEND ops.
      res.conn.sendFileFd = fileFd
      res.conn.sendFileOff = fileOff
      res.conn.sendFileRemain = remain
      discard res.conn.continueSendFile()
      if res.closeConn:
        res.conn.closeAfterDrain()
      return
    else:
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

    let rangeVal = req.getHeaderValue("range")
    if rangeVal.len > 0:
      let r = parseRange(rangeVal, fileSize)
      if r.ok:
        rangeStart = r.start
        rangeLen = min(r.length, chunkSize.int64)
        status = Http206
      elif rangeVal.isBytesUnit():
        closeFile(fileFd)
        res.status(Http416).send("Range Not Satisfiable")
        return

    res.sent = true
    var hdrBuf = res.bodyBytes
    var p = 0

    hdrAdd(hdrBuf, p, "HTTP/1.1 206 Partial Content\r\n", 30)

    hdrDate(hdrBuf, p)

    hdrAdd(hdrBuf, p, "Content-Length: ", 16)
    hdrUint(hdrBuf, p, rangeLen)
    hdrAdd(hdrBuf, p, "\r\n", 2)

    hdrAdd(hdrBuf, p, "Accept-Ranges: bytes\r\n", 22)

    let ext = getFileExt(path)
    let mimeType = if isExtension(ext): getMimeType(ext).get() else: "application/octet-stream"
    hdrAdd(hdrBuf, p, "Content-Type: ", 14)
    hdrAdd(hdrBuf, p, mimeType)
    hdrAdd(hdrBuf, p, "\r\n", 2)

    hdrAdd(hdrBuf, p, "Connection: keep-alive\r\n", 24)

    for (k, v) in res.headers:
      hdrAdd(hdrBuf, p, k)
      hdrAdd(hdrBuf, p, ": ", 2)
      hdrAdd(hdrBuf, p, v)
      hdrAdd(hdrBuf, p, "\r\n", 2)

    let rangeEnd = min(rangeStart + rangeLen - 1, fileSize - 1)
    hdrAdd(hdrBuf, p, "Content-Range: bytes ", 21)
    hdrUint(hdrBuf, p, rangeStart)
    hdrByte(hdrBuf, p, byte('-'))
    hdrUint(hdrBuf, p, rangeEnd)
    hdrByte(hdrBuf, p, byte('/'))
    hdrUint(hdrBuf, p, fileSize)
    hdrAdd(hdrBuf, p, "\r\n", 2)

    hdrAdd(hdrBuf, p, "\r\n", 2)

    type Part = tuple[data: ptr UncheckedArray[byte]; len: int]
    var parts {.noinit.}: array[6, Part]
    var count = 0
    parts[count] = (cast[ptr UncheckedArray[byte]](addr hdrBuf[0]), p); inc count
    discard res.conn.sendv(parts.toOpenArray(0, count - 1))

    discard seekFile(fileFd, rangeStart)

    if res.conn.isTlsActive() and not res.conn.ktlsTxActive():
      # No zero-copy sendfile over userspace TLS: read the file and send via
      # SSL_write. With kTLS TX offload the kernel frames the TLS records
      # itself, so the plain sendfile path below is safe to use instead.
      # Reuse the pooled res.bodyBytes as the chunk buffer.
      const TlsChunk = 65536
      res.bodyBytes.setLen(TlsChunk)
      var remain = rangeLen
      while remain > 0:
        let toRead = if remain > TlsChunk: TlsChunk else: int(remain)
        let n = readFile(fileFd, cast[ptr UncheckedArray[byte]](addr res.bodyBytes[0]), toRead)
        if n <= 0: break
        discard res.conn.send(res.bodyBytes.toOpenArray(0, int(n) - 1))
        remain -= n
      closeFile(fileFd)
      return

    var fileOff = rangeStart
    var remain = rangeLen

    when iouEnabled:
      # Same ordering constraint as sendFile: the header SEND op is async, so the
      # file must not be sent before the headers complete. The op-driven pump
      # waits for the headers to drain before streaming the file.
      res.conn.sendFileFd = fileFd
      res.conn.sendFileOff = fileOff
      res.conn.sendFileRemain = remain
      discard res.conn.continueSendFile()
      return
    else:
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
  ## Send an error response and close the connection. When no `msg` is given,
  ## the body defaults to the status code's reason phrase (statusText).
  res.status(code)
  res.header("Content-Type", "text/plain; charset=utf-8")
  res.close()
  res.send(if msg.len > 0: msg else: statusText(code))

proc getConn*(res: HttpResponse): Connection {.inline.} =
  ## Get the underlying TCP connection. Used by protocol upgrade
  ## handlers (e.g. WebSocket) that need direct access to the socket.
  res.conn

proc getClientIp*(res: HttpResponse): string {.inline.} =
  if res.conn != nil: res.conn.getClientIp() else: ""

proc markSent*(res: HttpResponse) {.inline.} =
  ## Mark this response as sent without writing any bytes.
  ## Used by upgrade handlers that send the response manually.
  res.sent = true

# ── HttpResponse pooling ──────────────────────────────────────────────────────────

proc acquireHttpResponse(server: HttpServer, conn: Connection): HttpResponse =
  if server.resPool.len > 0:
    result = server.resPool.pop()
    result.conn = conn
    result.server = server
    result.headers.setLen(0)
    result.bodyBytes.setLen(0)
    result.sent = false
    result.statusCode = uint16(Http200)
    result.closeConn = false
  else:
    result = HttpResponse(
      conn: conn, server: server, statusCode: uint16(Http200), sent: false, closeConn: false,
      headers: @[], bodyBytes: @[])

proc releaseHttpResponse(server: HttpServer, res: HttpResponse) {.inline.} =
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
  if server.reqPool.len < MaxReqPoolSize:
    server.reqPool.add(req)

# ── HttpServer lifecycle ─────────────────────────────────────────────────────

proc populatePools*(server: HttpServer; poolSize = 256)

proc newHttpServer*(loop: Loop; populate: bool = true): HttpServer =
  ## Create an HTTP server on the given event loop. Pools (parsers,
  ## responses, connections, read buffers) are prewarmed by default so the
  ## request hot path performs no allocations; pass `populate = false` to
  ## defer ~1 MB of startup allocations.
  let srv = HttpServer(
    tcpServers: @[],
    loop:      loop,
    handler:   nil,
    connRoots: initTable[int, ConnHttp](1024),
    parserPool: @[],
    reqPool:   @[],
    resPool:   @[],
    wsPool:    @[],
    sweepStale: @[],
    sslCtx:    nil,
    keepAliveMs: DefaultKeepAliveMs,
    maxBodySize: 0,
    maxStreamBodySize: 0,
    minStreamBodySize: 0,
    maxFileSize: 0,
    maxFieldSize: 0,
    maxConnections: 0,
    maxPipelineDepth: 0,
    readTimeoutMs: 30_000,
    wsIdleTimeoutMs: 0,
    timeoutSweepMs: 200,
    sweepTimer: TimerId(0)
  )
  if populate:
    srv.populatePools()
  srv

proc newHttpServer*(populate: bool = true): HttpServer =
  var eventLoop = newLoop()
  newHttpServer(eventLoop, populate)

proc start*(server: HttpServer, handler: OnRequestCallback, port: Port) =
  server.handler = handler
  server.listen("0.0.0.0", port.int)
  server.loop.run()

proc start*(server: HttpServer, handler: OnRequestCallback, ports: varargs[Port]) =
  ## Start the server on multiple ports on 0.0.0.0 with the same handler.
  ## `listen` is additive, so this is equivalent to calling `listen` for each
  ## port before `loop.run()`. At least one port is required.
  if ports.len == 0:
    raise newException(ValueError, "start: at least one Port is required")
  server.handler = handler
  for p in ports:
    server.listen("0.0.0.0", p.int)
  server.loop.run()

proc start*(server: HttpServer, handler: OnRequestCallback, address: string, ports: varargs[Port]) =
  ## Start on multiple ports bound to `address` (same address for all ports).
  if ports.len == 0:
    raise newException(ValueError, "start: at least one Port is required")
  server.handler = handler
  for p in ports:
    server.listen(address, p.int)
  server.loop.run()

proc stop*(server: HttpServer) =
  ## Stop the HTTP server and close all connections
  server.close()
  server.loop.close()

proc maybeArmBodyStream(server: HttpServer, ctx: ConnHttp, p: HttpParser)
  ## Forward declaration (defined near handleConnectionData): choose the body
  ## strategy at header time. Needed here because acquireConnHttp wires it as
  ## the parser's onHeadersComplete hook.

proc acquireParser(server: HttpServer): HttpParser =
  if server.parserPool.len > 0:
    result = server.parserPool.pop()
    result.reset()
  else:
    result = newHttpParser()
  result.maxBodySize = server.maxBodySize
  result.maxStreamBodySize = server.maxStreamBodySize

proc releaseParser(server: HttpServer, parser: HttpParser) {.inline.} =
  if server.parserPool.len < MaxParserPoolSize:
    parser.reset()
    server.parserPool.add(parser)

proc wsPoolPop*(server: HttpServer): ref RootObj {.inline.} =
  ## Pop an idle WebSocket connection from the pool, or nil when empty.
  ## Kept opaque (`ref RootObj`) so httpserver does not need to know WsConnection.
  if server.wsPool.len > 0: server.wsPool.pop() else: nil

proc wsPoolAdd*(server: HttpServer, ws: ref RootObj) {.inline.} =
  ## Return an idle WebSocket connection to the pool (dropped when full).
  if server.wsPool.len < MaxWsPoolSize:
    server.wsPool.add(ws)

proc setKeepAliveTimeout*(server: HttpServer, ms: int) =
  ## Set the keep-alive idle timeout in milliseconds. 0 disables it.
  server.keepAliveMs = ms

proc acquireConnHttp(server: HttpServer, conn: Connection): ConnHttp =
  ## Take a per-connection session from the pool (or allocate). The parser is
  ## always freshly acquired: pooled sessions hold no parser while idle, so
  ## ownership never doubles. The session starts in `pendingConns` (unhashed);
  ## `markIdle` promotes it to `connRoots` once its first request completes.
  if server.connHttpPool.len > 0:
    result = server.connHttpPool.pop()
    result.parser = acquireParser(server)
    result.conn = conn
    result.fd = conn.fd.int
    result.lastActive = monoMs()
    result.idleAfter = 0
  else:
    result = ConnHttp(parser: acquireParser(server))
    result.conn = conn
    result.fd = conn.fd.int
    result.lastActive = monoMs()
  # Pre-arm body streaming: when this connection's parser finishes a request's
  # headers, decide the body strategy before the first body byte is consumed
  # (see maybeArmBodyStream). Set once per connection — pooled parsers arrive
  # with hooks cleared (reset), and the per-request fired flag is cleared by
  # resetForNext so pipelined requests re-arm independently.
  let srv = server
  let session = result
  result.parser.onHeadersComplete = proc(p: HttpParser) {.closure.} =
    srv.maybeArmBodyStream(session, p)
  result.inRoots = false
  result.pendingIdx = server.pendingConns.len
  server.pendingConns.add(result)

proc pendingRemove(server: HttpServer, ctx: ConnHttp) {.inline.} =
  ## O(1) swap-remove from `pendingConns`. No-op when already removed.
  let i = ctx.pendingIdx
  if i < 0 or i >= server.pendingConns.len: return
  if server.pendingConns[i] != ctx:
    # Index went stale without going through the helpers — linear fallback
    # so the entry can never leak (should be unreachable).
    for j in 0 ..< server.pendingConns.len:
      if server.pendingConns[j] == ctx:
        server.pendingConns.del(j)
        for k in j ..< server.pendingConns.len:
          server.pendingConns[k].pendingIdx = k
        break
    ctx.pendingIdx = -1
    return
  let last = server.pendingConns.len - 1
  if i != last:
    server.pendingConns[i] = server.pendingConns[last]
    server.pendingConns[i].pendingIdx = i
  server.pendingConns.setLen(last)
  ctx.pendingIdx = -1

proc releaseConnHttp(server: HttpServer, ctx: ConnHttp) {.inline.} =
  ## Return a session to the pool after full reset. Callers must have already
  ## removed it from `connRoots`/`pendingConns` and cleaned streaming state.
  ctx.conn = nil
  ctx.fd = 0
  ctx.inRoots = false
  ctx.pendingIdx = -1
  ctx.lastActive = 0
  ctx.idleAfter = 0
  ctx.sessionStreamPath = ""
  ctx.streamer = nil
  # NOTE: parser released by the caller (removeSession) before this runs;
  # sessionStreamFile was closed with its path and is unreachable while
  # sessionStreamPath is empty.
  if server.connHttpPool.len < MaxConnHttpPoolSize:
    server.connHttpPool.add(ctx)

proc removeSession*(server: HttpServer, conn: Connection) =
  let ctx = cast[ConnHttp](conn.data)
  if ctx == nil: return
  if ctx.inRoots:
    # conn.fd is already -1 when called after conn.close() (EOF/Error/
    # fast-close paths), so delete by the fd stored at session creation.
    server.connRoots.del(ctx.fd)
    if conn.fd.int != ctx.fd:
      server.connRoots.del(conn.fd.int)
    ctx.inRoots = false
  else:
    server.pendingRemove(ctx)
  if ctx.sessionStreamPath.len > 0:
    ctx.sessionStreamFile.close()
    removeFile(ctx.sessionStreamPath)
    ctx.sessionStreamPath = ""
  if ctx.streamer != nil:
    ctx.streamer[].cleanup()
    ctx.streamer = nil
  if ctx.parser != nil:
    releaseParser(server, ctx.parser)
    ctx.parser = nil
  conn.data = nil
  server.releaseConnHttp(ctx)

proc markIdle(server: HttpServer, conn: Connection) =
  ## Mark a connection idle: a request just completed, so the keep-alive
  ## timeout now applies. Refreshes both stamps from the clock sampled once
  ## per event-loop iteration — zero per-request `clock_gettime` calls; the
  ## ~1 ms quantization is unobservable next to the 5 s / 30 s timeouts.
  ## Falls back to a direct sample outside a running loop (unit tests).
  ##
  ## Timeout semantics are preserved: after this call `idleAfter >= lastActive`
  ## so the sweep applies keepAliveMs from completion time. A connection stuck
  ## mid-request keeps the stamp of its last completion (or accept time for a
  ## brand-new connection), so readTimeoutMs still bounds slowloris drips —
  ## slightly more strictly than before, since individual drips no longer
  ## restart the window.
  let ctx = cast[ConnHttp](conn.data)
  if ctx == nil: return
  let now = if pollNowMs != 0: pollNowMs else: monoMs()
  ctx.lastActive = now
  ctx.idleAfter = now
  if not ctx.inRoots:
    # First completed request: promote from the unhashed pending list to
    # `connRoots`, where the sweep applies keepAliveMs from now on.
    server.pendingRemove(ctx)
    server.connRoots[ctx.fd] = ctx
    ctx.inRoots = true

proc closeStale(server: HttpServer, ctx: ConnHttp) =
  ## Close a connection that exceeded its read/keep-alive timeout.
  let c = ctx.conn
  if c == nil or c.state == Closed: return
  if c.state == Connected and c.sendFileFd >= 0: return  # zero-copy response in flight
  server.removeSession(c)
  c.close()

proc sweepTimeouts(server: HttpServer) =
  ## Lazy timeout enforcement: a single periodic pass over active connections.
  ## Enforces readTimeoutMs (mid-request stalls) and keepAliveMs (idle
  ## keep-alive) without any per-request timer add/cancel on the hot path.
  if server.keepAliveMs <= 0 and server.readTimeoutMs <= 0:
    return
  let now = monoMs()
  server.sweepStale.setLen(0)
  if server.readTimeoutMs > 0:
    # Sessions before their first completed request: only the read timeout
    # applies (they never went idle). This preserves the slowloris bound that
    # the eager `connRoots` insert used to provide.
    for ctx in server.pendingConns:
      if ctx.conn != nil and ctx.conn.state != Closed and
         now - ctx.lastActive > server.readTimeoutMs:
        server.sweepStale.add(ctx)
  for ctx in server.connRoots.values:
    if ctx.conn != nil and ctx.conn.state == Closing:
      # Graceful close in progress (response sent, FIN sent): reclaim if the
      # peer never finishes reading/closing.
      if server.keepAliveMs > 0 and now - ctx.lastActive > server.keepAliveMs:
        server.sweepStale.add(ctx)
      continue
    if ctx.idleAfter >= ctx.lastActive:
      # Idle — waiting for the next request → keep-alive applies.
      if server.keepAliveMs > 0 and now - ctx.idleAfter > server.keepAliveMs:
        server.sweepStale.add(ctx)
    else:
      # A request is in progress → read timeout applies.
      if server.readTimeoutMs > 0 and now - ctx.lastActive > server.readTimeoutMs:
        server.sweepStale.add(ctx)
  for ctx in server.sweepStale:
    server.closeStale(ctx)

proc startTimeoutSweep(server: HttpServer) =
  ## Arm the single server-wide timeout sweep timer (one timer per server, not
  ## per request). `timeoutSweepMs` is the sweep granularity.
  if server.sweepTimer != TimerId(0): return
  let interval = max(server.timeoutSweepMs, 25)
  server.sweepTimer = server.loop.addInterval(interval) do (id: int):
    server.sweepTimeouts()

# ── Request dispatch ─────────────────────────────────────────────────────────

proc dispatchRequest(server: HttpServer, conn: Connection,
                     req: HttpRequest) =
  req.conn = conn
  let res = acquireHttpResponse(server, conn)
  if req.getConnectionClose():
    res.closeConn = true
  if server.handler != nil:

    server.handler(req, res)
  else:
    res.sendError(Http500, "No handler configured")
  releaseHttpResponse(server, res)


proc openStreamFile(server: HttpServer, ctx: ConnHttp, p: HttpParser): bool =
  ## Create the private temp file for a streamed body and install the
  ## file-writing onBodyData. Returns false (with p in PhaseError/500) when
  ## no temp file could be created.
  let dir = getTempDir()
  discard existsOrCreateDir(dir)
  for attempt in 0 ..< 8:
    ctx.sessionStreamPath = dir / $genOid()
    try:
      ctx.sessionStreamFile = openPrivateFile(ctx.sessionStreamPath)
      p.onBodyData = proc(data: openArray[byte]; done: bool) {.closure.} =
        if data.len > 0:
          discard ctx.sessionStreamFile.writeBuffer(unsafeAddr data[0], data.len)
        if done:
          ctx.sessionStreamFile.close()
      return true
    except IOError:
      ctx.sessionStreamPath = ""
  p.setError(Http500)
  return false

proc maybeArmBodyStream(server: HttpServer, ctx: ConnHttp, p: HttpParser) =
  ## Choose the body strategy as soon as the headers are known. Invoked via
  ## onHeadersComplete (before any body byte is consumed — including bytes
  ## already sitting in the same packet), and once defensively after feed.
  ## Small bodies stay buffered so getBody*/bodyView keep working; large or
  ## unknown-size bodies stream, keeping p.buf at ~headers:
  ##   - multipart/form-data (any Content-Length, or chunked) → incremental
  ##     MultipartStreamerRef from the first body byte; handlers keep using
  ##     getMultipart() unchanged (it returns req.streamer directly when
  ##     pre-populated). Eager arming also rejects over-limit file parts
  ##     early, without waiting for the rest of the body.
  ##   - Content-Length >= minStreamBodySize → temp file (req.streamPath).
  ##   - chunked, other types → spill to temp file once decoded bytes reach
  ##     minStreamBodySize (threshold hook); small chunked stays buffered.
  if p.onBodyData != nil or p.streamingBody: return
  if p.phase != PhaseBody or p.isComplete(): return
  var isMultipart = false
  if p.contentLength > 0 or p.transferChunked:
    isMultipart = p.peekContentType().startsWith("multipart/form-data")
  # Bound auto-streamed uploads: server.maxBodySize when set, otherwise a
  # hard cap — a client must not be able to fill the disk/temp dir with an
  # unbounded upload. (Previously maxBodySize=0 meant unlimited disk writes.)
  let uploadCap = if server.maxBodySize > 0: server.maxBodySize
                  elif server.maxStreamBodySize > 0: server.maxStreamBodySize
                  else: int64(MaxStreamBodySize)
  let streamThreshold = if server.minStreamBodySize > 0: server.minStreamBodySize
                        else: int64(MinStreamBodySize)
  # Multipart of any size streams from the first body byte: the streamer
  # enforces per-file/per-field/total caps inline, so over-limit parts are
  # rejected early without waiting for the rest of the body (and a large
  # single-packet upload never sits in p.buf). Handlers are unaffected:
  # getMultipart() returns the pre-populated req.streamer directly.
  if isMultipart and (p.contentLength > 0 or p.transferChunked):
    let ct = p.peekContentType()  # cache hit from the check above: no copy
    let fileCap = if server.maxFileSize > 0: server.maxFileSize
                  else: uploadCap
    let fieldCap = if server.maxFieldSize > 0: server.maxFieldSize
                   else: uploadCap
    # bodySize 0 (chunked): total unknown; the parser-level streamCap still
    # bounds total decoded bytes, and per-file/per-field limits apply inline.
    ctx.streamer = newMultipartStreamerRef(ct,
      bodySize = if p.contentLength > 0: p.contentLength.int64 else: 0,
      sizeLimit = MultipartSizeLimit(maxBodySize: uploadCap,
                                     maxFileSize: fileCap,
                                     maxFieldSize: fieldCap))
    let ms = ctx.streamer
    p.onBodyData = proc(data: openArray[byte]; done: bool) {.closure.} =
      ms[].feed(data)  # empty-safe no-op; completion detected via boundary
  elif p.contentLength >= streamThreshold:
    discard server.openStreamFile(ctx, p)
  elif p.transferChunked:
    # Unknown size: stay buffered until the decoded bytes prove large.
    p.bodyThreshold = streamThreshold
    p.onBodyThreshold = proc(pp: HttpParser) {.closure.} =
      discard server.openStreamFile(ctx, pp)

proc handleConnectionData(server: HttpServer, conn: Connection,
                          data: openArray[byte]) =
  ## Feed incoming bytes into the per-connection parser.
  ## Supports HTTP/1.1 pipelining: if multiple complete requests arrive
  ## in the same TCP read, all of them are processed in order.
  ## Large bodies never sit in the parser buffer: the onHeadersComplete hook
  ## (wired per connection) pre-arms tempfile/multipart streaming before the
  ## first body byte is consumed, so a large single-packet upload peaks at
  ## ~headers. Handlers read big bodies via `req.streamPath`/`streamToFile`
  ## (raw) or `req.getMultipart()` (multipart); small bodies stay buffered
  ## for `getBodyString`/`bodyView`.
  let ctx = if conn.data != nil: cast[ConnHttp](conn.data)
            else:
              let c = server.acquireConnHttp(conn)
              conn.data = cast[pointer](c)
              c
  let p = ctx.parser
  try:
    p.feed(data)
  except MultipartSizeLimitError:
    # A multipart upload exceeded a configured size limit — the shared error
    # handling below cleans up streaming state and replies 413 instead of
    # letting the exception crash the event loop.
    p.setError(Http413)
  except MultipartInvalidHeader:
    # Malformed multipart part headers — same handling, respond 400.
    p.setError(Http400)
  except MultipartConfigError:
    # Garbage multipart boundary in Content-Type — same handling, 400.
    p.setError(Http400)
  except IOError, OSError:
    # Temp-file write failed mid-stream (disk full/unlinked tmp) — reply 500;
    # the shared error handling below closes and removes the partial file.
    p.setError(Http500)

  if p.expectContinue and p.phase == PhaseBody:
    let continueResp = "HTTP/1.1 100 Continue\r\n\r\n"
    discard conn.send(continueResp.toOpenArrayByte(0, continueResp.len - 1))
    p.expectContinue = false

  # Defensive re-arm: headers normally complete inside feed (firing
  # onHeadersComplete synchronously), but any path that reached PhaseBody
  # with no strategy yet gets one here before dispatch below.
  if p.phase == PhaseBody and not p.isComplete():
    server.maybeArmBodyStream(ctx, p)

  var pipelineCount = 0
  while p.isComplete():
    if server.maxPipelineDepth > 0 and pipelineCount >= server.maxPipelineDepth:
      break
    inc pipelineCount
    let req = server.acquireRequest(p)
    if ctx.sessionStreamPath.len > 0:
      req.streamPath = ctx.sessionStreamPath
      ctx.sessionStreamPath = ""
      p.onBodyData = nil
    if ctx.streamer != nil:
      req.streamer = ctx.streamer
      ctx.streamer = nil
      p.onBodyData = nil
    server.dispatchRequest(conn, req)
    releaseRequest(server, req)
    if conn.data == nil:
      return
    if conn.state != Connected:
      # Fast close (`Connection: close` via closeAfterSend) tore the fd down
      # inline. Stop: session cleanup + pool release run once in the outer
      # handleClientRead/sharedCb. Parsing further pipelined bytes on a dead
      # fd would only burn cycles (and a second dispatch would send on a
      # closed connection).
      return
    ctx.parser.resetForNext()
    p.tryAdvance()
    if conn.sendFileFd >= 0:
      break

  # All pipelined requests handled. If at least one request completed, the
  # connection is now idle waiting for the next one — the timeout sweep will
  # apply keepAliveMs. If the current request is still incomplete (slowloris),
  # it stays in the read-timeout state until readTimeoutMs.
  if conn.state == Connected and conn.data != nil and conn.sendFileFd < 0 and
     pipelineCount > 0:
    server.markIdle(conn)

  if p.isError():
    if ctx.streamer != nil:
      ctx.streamer[].cleanup()
      ctx.streamer = nil
    if ctx.sessionStreamPath.len > 0:
      ctx.sessionStreamFile.close()
      removeFile(ctx.sessionStreamPath)
      ctx.sessionStreamPath = ""
    p.onBodyData = nil
    let errCode = p.error()
    let res = acquireHttpResponse(server, conn)
    res.sendError(errCode)
    ctx.parser.reset()

# ── Listen ───────────────────────────────────────────────────────────────────

proc buildTcpServer(server: HttpServer): TcpServer =
  ## Create the underlying TcpServer, wrapping accepted connections in TLS when
  ## `server.sslCtx` is set (implicit TLS, e.g. HTTPS on port 443).
  result = newTcpServer(server.loop,
    onData = proc(conn: Connection, data: openArray[byte]) =
      server.handleConnectionData(conn, data)
    ,
    onAccept = if server.sslCtx != nil:
        proc(conn: Connection) =
          conn.wrapTls(server.sslCtx)
      else:
        nil
    ,
    onClose = proc(conn: Connection) =
      server.removeSession(conn)
    ,
  )
  result.maxConnections = server.maxConnections

proc listen*(server: HttpServer, address: string, port: int) =
  ## Bind an additional TCP listen socket. Additive — call repeatedly before
  ## `loop.run()` to serve the same handler on multiple ports (same address
  ## per call; use multiple calls with different addresses if needed, or
  ## `start(handler, Port(...), Port(...))` for the `0.0.0.0` shorthand).
  ## Each call creates a new `TcpServer` sharing the same `Loop` and timeout
  ## sweep. The sweep is started once. If `populatePools` pre-created an
  ## unbound TcpServer (fd == -1), the first `listen` reuses it instead of
  ## leaking an idle server.
  if server.tcpServers.len == 1 and server.tcpServers[0].fd.int < 0:
    # `populatePools` pre-created an unbound TcpServer (fd == -1) solely to
    # hold the pre-warmed connPool. Migrate the warmed pool into the fresh
    # server (which has up-to-date sslCtx/maxConnections closures) instead of
    # dropping it: each pooled Connection owns a dedicated read buffer that
    # would otherwise leak, and re-warming would redo the allocations.
    # Stale `server` back-pointers are rebound lazily by acquireConnection.
    let ts = server.buildTcpServer()
    ts.connPool = move server.tcpServers[0].connPool
    server.tcpServers.setLen(0)
    ts.listen(address, port)
    server.tcpServers.add(ts)
  else:
    let ts = server.buildTcpServer()
    ts.listen(address, port)
    # Only add after a successful bind, so a failed bind does not leak a
    # half-initialized server into the list.
    server.tcpServers.add(ts)
  server.startTimeoutSweep()

proc adoptListenFd*(server: HttpServer, fd: SocketHandle) =
  ## Serve on an already-bound listen socket (see `createListenSocket`),
  ## adding one `TcpServer` per call just like `listen`. Intended for
  ## multi-worker servers, where a single listen socket is created once and
  ## adopted by every worker's loop; ownership stays with the creator, so
  ## `close()` never sockCloses it.
  if server.tcpServers.len == 1 and server.tcpServers[0].fd.int < 0:
    # `populatePools` pre-created an unbound TcpServer; migrate its pool as
    # in listen() above so the warmed Connection buffers are not leaked.
    let ts = server.buildTcpServer()
    ts.connPool = move server.tcpServers[0].connPool
    server.tcpServers.setLen(0)
    ts.adoptListenFd(fd)
    server.tcpServers.add(ts)
  else:
    let ts = server.buildTcpServer()
    ts.adoptListenFd(fd)
    server.tcpServers.add(ts)
  server.startTimeoutSweep()

when not defined(windows):
  proc listenUnix*(server: HttpServer, path: string; mode: int = 0o660) =
    ## Listen on a Unix domain socket. `mode` is the file permission bits for the socket.
    if server.tcpServers.len == 1 and server.tcpServers[0].fd.int < 0:
      # Same connPool migration as in listen() above (see comment there).
      let ts = server.buildTcpServer()
      ts.connPool = move server.tcpServers[0].connPool
      server.tcpServers.setLen(0)
      ts.listenUnix(path, mode)
      server.tcpServers.add(ts)
    else:
      let ts = server.buildTcpServer()
      ts.listenUnix(path, mode)
      server.tcpServers.add(ts)
    server.startTimeoutSweep()

proc close*(server: HttpServer) =
  ## Close the server and all active connections
  if server.sweepTimer != TimerId(0):
    server.loop.cancelTimer(server.sweepTimer)
    server.sweepTimer = TimerId(0)
  for ts in server.tcpServers:
    ts.close()
  server.tcpServers.setLen(0)
  server.connRoots.clear()
  server.pendingConns.setLen(0)
  server.parserPool.setLen(0)

proc ensureTcpServer*(server: HttpServer) =
  ## Ensure the server has at least one TCP server instance
  if server.tcpServers.len > 0: return
  server.tcpServers.add(server.buildTcpServer())

proc tcpServer*(server: HttpServer): TcpServer {.inline.} =
  ## Backwards-compat accessor: the first (primary) TcpServer, or nil.
  ## Prefer `tcpServers` for multi-port cases.
  if server.tcpServers.len > 0: server.tcpServers[0] else: nil

proc `tcpServer=`*(server: HttpServer, ts: TcpServer) {.inline.} =
  ## Backwards-compat setter. Replaces the primary server.
  if server.tcpServers.len > 0:
    server.tcpServers[0] = ts
  elif ts != nil:
    server.tcpServers.add(ts)

proc populatePools*(server: HttpServer; poolSize = 256) =
  ## Pre-allocate parsers, responses, connections, and buffers to
  ## eliminate all allocations on the request hot path.
  if server.tcpServers.len == 0:
    server.ensureTcpServer()
  for i in 0 ..< poolSize:
    if server.parserPool.len < MaxParserPoolSize:
      server.parserPool.add(newHttpParser())
    if server.resPool.len < MaxResPoolSize:
      server.resPool.add(HttpResponse(
        conn: nil, statusCode: uint16(Http200), sent: false, closeConn: false,
        headers: @[], bodyBytes: @[]))
    if server.connHttpPool.len < MaxConnHttpPoolSize:
      # Pre-warm session shells (no parser while idle; acquireConnHttp assigns
      # one, so pooled sessions never double-own a parser).
      server.connHttpPool.add(ConnHttp())
    # Pre-warm the connection pool on the primary TcpServer. Additional
    # listeners share the loop's bufPool; they allocate connections on demand.
    # Each pooled connection owns a DEDICATED read buffer: sharing one pointer
    # between bufPool and a pooled Connection would hand the same 4KB to two
    # live connections (data corruption), so the spare and the dedicated bufs
    # are allocated separately.
    let primary = server.tcpServers[0]
    if primary.connPool.len < MaxConnPoolSize:
      primary.connPool.add(newConnection(
        SocketHandle(-1), server.loop, primary,
        cast[ptr UncheckedArray[byte]](allocShared(DefaultBufSize)),
        DefaultBufSize))
    if server.loop.bufPool.len < MaxBufPoolSize:
      server.loop.bufPool.add(
        cast[ptr UncheckedArray[byte]](allocShared(DefaultBufSize)))

proc addConnection*(server: HttpServer, fd: SocketHandle) {.inline.} =
  ## Add an existing TCP connection to the server
  server.ensureTcpServer()
  server.tcpServers[0].injectFd(fd)

proc getLoop*(server: HttpServer): Loop {.inline.} =
  ## Get the event loop associated with this server.
  server.loop

when not defined(windows):
  proc c_realpath(path: cstring, resolved: cstring): cstring {.
    importc: "realpath", header: "<stdlib.h>".}

proc resolveReal*(path: string): string =
  ## Canonical absolute path with symlinks resolved. A symlink (or, on Windows,
  ## a junction/reparse point) inside a serve root that points outside must not
  ## escape the root, so static file serving verifies the resolved path. Falls
  ## back to absolutePath when the path does not exist.
  when defined(windows):
    result = winpath.resolveRealWindows(path)
  else:
    var buf {.noinit.}: array[4096, char]
    let r = c_realpath(path.cstring, cast[cstring](addr buf[0]))
    if r != nil:
      result = $cast[cstring](addr buf[0])
      if result.len > 0: return
    result = absolutePath(path)

proc withinRoot*(root, path: string): bool =
  ## True when `path` is `root` itself or sits directly under it.
  path == root or path.startsWith(root & "/")

proc serveStatic*(res: HttpResponse, req: HttpRequest,
                  urlPrefix: string, fsRoot: string,
                  indexFiles: openArray[string] = ["index.html", "index.htm"]): bool =
  ## Serve static files from `fsRoot` for requests whose path starts with `urlPrefix`.
  ## Path traversal protection: rejects paths containing ".." or "~".
  ## Returns true if the file was served, false if not found (caller should send 404).
  ## Zero-copy: uses `sendFile` internally, no body buffering.
  ##
  ## The prefix is matched at a path-component boundary: urlPrefix="/static"
  ## serves "/static/..." but NOT the sibling-prefix path "/staticx/...".
  ## Both "/static" and "/static/" are accepted as the prefix.
  let path = req.getPath()
  # Normalize the prefix: drop a trailing slash so the boundary check is uniform.
  let prefix = if urlPrefix.len > 0 and urlPrefix[^1] == '/':
                 urlPrefix[0 .. ^2]
               else:
                 urlPrefix
  if path != prefix and not path.startsWith(prefix & "/"):
    return false
  var relPath = path[prefix.len .. ^1]
  # Strip the single separating slash (relPath is "/file" or "/dir/file").
  if relPath.len > 0 and relPath[0] == '/':
    relPath = relPath[1 .. ^1]
  if relPath.len == 0:
    # Request for the static root itself — try index files.
    for index in indexFiles:
      let indexPath = fsRoot / index
      if fileExists(indexPath):
        res.sendFile(indexPath, req, closeConn = false, contentDisposition = false)
        return true
    return false
  if relPath.contains("..") or relPath.contains("~"):
    res.status(Http403).header("Content-Type", "text/plain; charset=utf-8").send("Forbidden")
    return true
  let fullPath = fsRoot / relPath
  # Reject symlink escapes: a symlink inside fsRoot pointing outside would
  # otherwise be served. Resolve both and require the real path under the root.
  if not withinRoot(resolveReal(fsRoot), resolveReal(fullPath)):
    res.status(Http403).header("Content-Type", "text/plain; charset=utf-8").send("Forbidden")
    return true
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

func headerValue(headers: HttpHeaders, key: string): string {.inline.} =
  if headers.hasKey(key):
    result = $headers[key]
  else:
    result = ""

proc serveFile*(res: HttpResponse, req: HttpRequest, path: string;
                fsRoot: string = "";
                contentType: string = "";
                attach: bool = false;
                etag: string = "";
                lastModified: string = "";
                chunkSize: int64 = 0): bool =
  ## High-level static file serving with resume download support.
  ## Handles Range, If-Range, If-None-Match, If-Modified-Since, and ETag.
  ## Zero-copy: uses sendFile internally (sendfile syscall).
  ## Returns true if the file was served, false if file not found.
  ##
  ## When `etag` is empty, a strong ETag is auto-computed from
  ## file size and mtime. When `fsRoot` is set, path traversal
  ## attempts are rejected with 403.
  ## `chunkSize > 0` enables byte-limited streaming for media seeking.
  {.gcsafe.}:
    if res.sent: return true

    if fsRoot.len > 0:
      if path.contains("..") or path.contains("~"):
        res.status(Http403).header("Content-Type", "text/plain; charset=utf-8").send("Forbidden")
        return true
      # Path must equal fsRoot or sit directly under it — a bare startsWith
      # check would also accept sibling dirs sharing the prefix (e.g.
      # fsRoot="/var/www" matching "/var/www2/..."), a path-confusion escape.
      if path != fsRoot and not path.startsWith(fsRoot & "/"):
        res.status(Http403).header("Content-Type", "text/plain; charset=utf-8").send("Forbidden")
        return true
      # Symlink escape: a symlink inside fsRoot pointing outside must not be
      # served. Resolve both sides and verify the real path stays under the root.
      if not withinRoot(resolveReal(fsRoot), resolveReal(path)):
        res.status(Http403).header("Content-Type", "text/plain; charset=utf-8").send("Forbidden")
        return true

    let fileFd = openFileRead(path)
    if fileFd < 0:
      return false
    var fileSize = getFileSize(fileFd)
    closeFile(fileFd)
    if fileSize < 0:
      return false

    let mtime = getLastModificationTime(path)
    let fileETag = if etag.len > 0: etag
                   else: "\"" & $fileSize & "-" & $mtime.toUnix & "\""
    let fileMTime = if lastModified.len > 0: lastModified
                    else: format(mtime, "ddd, dd MMM yyyy HH:mm:ss") & " GMT"

    let reqHeaders = req.getHeaders()
    let ifNoneMatch = headerValue(reqHeaders, "If-None-Match")
    let ifModifiedSince = headerValue(reqHeaders, "If-Modified-Since")
    let ifRange = headerValue(reqHeaders, "If-Range")

    if ifNoneMatch.len > 0:
      if ifNoneMatch == "*" or ifNoneMatch == fileETag:
        res.status(Http304)
        res.header("ETag", fileETag)
        res.header("Last-Modified", fileMTime)
        res.header("Accept-Ranges", "bytes")
        res.send()
        return true

    if ifModifiedSince.len > 0 and ifNoneMatch.len == 0:
      try:
        let since = parse(ifModifiedSince, "ddd, dd MMM yyyy HH:mm:ss 'GMT'", utc())
        if mtime <= since.toTime:
          res.status(Http304)
          res.header("ETag", fileETag)
          res.header("Last-Modified", fileMTime)
          res.header("Accept-Ranges", "bytes")
          res.send()
          return true
      except:
        discard

    var honorRange = true
    if ifRange.len > 0:
      let matchesEtag = ifRange == fileETag
      var matchesMtime = false
      try:
        let rangeDate = parse(ifRange, "ddd, dd MMM yyyy HH:mm:ss 'GMT'", utc())
        matchesMtime = mtime == rangeDate.toTime
      except:
        discard
      if not matchesEtag and not matchesMtime:
        honorRange = false

    res.header("ETag", fileETag)
    res.header("Last-Modified", fileMTime)

    if chunkSize > 0:
      res.streamFile(path, req, chunkSize)
    elif not honorRange:
      res.sendFile(path, req, closeConn = false, contentDisposition = attach, skipRange = true)
    else:
      res.sendFile(path, req, closeConn = false, contentDisposition = attach)
    return true
