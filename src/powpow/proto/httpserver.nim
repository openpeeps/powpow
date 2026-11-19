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

import pkg/[mimedb, multipart, buffalo]
import pkg/archive/gzipf
from pkg/archive/io import Output, newOutput, reset, outputBytes
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
    compressArmed: bool         ## res.compress() requested: attempt gzip for
      ## this response even when server.compressEnabled is off

  OnRequestCallback* = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.}
    ## User-provided callback invoked for every parsed HTTP request.
    ## Higher-level frameworks implement routing on top of this.

  AccessLogEntry* = object
    ## One completed HTTP request for `onAccessLog`. Fired at dispatch
    ## return (handler time); for chunked/SSE streams this is time-to-first-byte
    ## (`streaming` is true and the stream still owns the connection).
    clientIp*: string
    httpMethod*: HttpMethod
    path*: string
    statusCode*: uint16
    durationMs*: int64
    streaming*: bool

  OnAccessLog* = proc(entry: AccessLogEntry) {.closure, gcsafe.}
    ## Optional per-request hook: `server.onAccessLog = proc(e) = ...`.
    ## Runs on the loop thread. Nil (default) disables logging entirely —
    ## no entry is built on the hot path when unset.

  DrainCallback* = proc() {.closure, gcsafe.}
    ## Fired once on the loop thread when `drain` empties the server.
    ## Tear down there (`server.close()` and/or `loop.stop()`).

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
    streamingResponse: bool     ## true while a chunked/SSE stream owns the
      ## connection: the sweep applies readTimeoutMs from the last chunk
      ## (touched per write), and `markIdle` is deferred to stream close
    acceptsGzip: bool           ## client allows gzip (parsed once at dispatch
      ## when compression is enabled; HEAD never sets it)
    proxyPending: bool          ## PROXY header not yet consumed (first reads
      ## only; set when server.proxyProtocol is on)
    proxyBuf: seq[byte]         ## held preface bytes until the header completes
      ## (bounded by ProxyHoldCap; cleared after consumption)

  HttpServer* = ref object
    tcpServers*: seq[TcpServer]
    loop:      Loop
    ownsLoop*: bool
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
    compressEnabled*: bool
      ## Master switch for response compression (default off). When on,
      ## `send()` negotiates gzip via Accept-Encoding; `res.compress()`
      ## forces the attempt for one response regardless of this flag.
    compressMinLen*: int
      ## Bodies below this size are never compressed (default 1024).
    compressLevel*: int
      ## Gzip level 0..9 (default 6); only affects the header hint byte,
      ## the fixed-Huffman encoder ignores it.
    proxyProtocol*: bool
      ## Accept haproxy PROXY v1/v2 ingress (default off). When on, each new
      ## connection must start with a PROXY header; its source address
      ## replaces the socket peer as the client IP (logs, req.getClientIp).
      ## Malformed prefaces get 400 + close (fail closed, never fed to the
      ## HTTP parser). Plaintext listeners only for now: with TLS the
      ## handshake would consume the plaintext header, so enabling both
      ## fails the handshake.
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
    onAccessLog*: OnAccessLog
      ## Structured per-request hook (nil = disabled, zero hot-path cost).
    draining*: bool
      ## Graceful shutdown in progress: listeners closed, idle sessions shut,
      ## in-flight requests/streams run to completion. See `drain`.
    drainTimer: TimerId   ## force-close deadline while draining
    drainCb: DrainCallback ## fired once when the last session closes

const
  DefaultKeepAliveMs* = 5_000
  DefaultReadTimeoutMs* = 30_000
    ## Mid-request/partial-request timeout matching `newHttpServer`.
  DefaultTimeoutSweepMs* = 200
    ## Lazy timeout-sweep interval matching `newHttpServer`.
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
  ## `sendfile(2)` even over TLS). See `configureKtls` (net/tls).
  res.conn.ktlsTxActive()

proc ktlsActive*(res: HttpResponse): bool {.inline.} =
  ## True when the kernel terminates TLS on this response's connection in
  ## either direction. When false, file bodies take the userspace chunk loop
  ## rather than zero-copy `sendfile(2)`. See `ktlsTxActive` (net/tls).
  res.conn.ktlsActive()

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
  of 300: "Multiple Choices"
  of 301: "Moved Permanently"
  of 302: "Found"
  of 303: "See Other"
  of 305: "Use Proxy"
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

func chunkHexInto(buf: var openArray[byte], n: int): int =
  ## Write lowercase hex of `n` into `buf`, return the digit count.
  ## Stack-only, no allocation. `n == 0` writes `"0"`.
  if n == 0:
    buf[0] = byte('0')
    return 1
  var tmp: array[16, byte]
  var len = 0
  var v = n
  while v > 0:
    let d = v and 0xF
    tmp[len] = if d < 10: byte(ord('0') + d) else: byte(ord('a') + d - 10)
    inc len
    v = v shr 4
  for i in 0 ..< len:
    buf[i] = tmp[len - 1 - i]
  len

proc sendRawChunk(conn: Connection, p: pointer, n: int) {.inline.} =
  ## Emit one `Transfer-Encoding: chunked` chunk (`hex CRLF data CRLF`) via
  ## `sendv` — the payload is never copied. `n <= 0` is a no-op (an empty
  ## chunk would terminate the stream).
  if n <= 0 or p == nil:
    return
  var hexBuf: array[18, byte]
  let hxLen = chunkHexInto(hexBuf, n)
  hexBuf[hxLen] = byte('\r')
  hexBuf[hxLen + 1] = byte('\n')
  var tail: array[2, byte] = [byte('\r'), byte('\n')]
  var parts: array[3, tuple[data: ptr UncheckedArray[byte], len: int]]
  parts[0] = (cast[ptr UncheckedArray[byte]](addr hexBuf[0]), hxLen + 2)
  parts[1] = (cast[ptr UncheckedArray[byte]](p), n)
  parts[2] = (cast[ptr UncheckedArray[byte]](addr tail[0]), 2)
  discard conn.sendv(parts.toOpenArray(0, 2))

# ── Response compression (opt-in gzip) ──────────────────────────────────────

var gzipStrm {.threadvar.}: GzipStream
  ## Deflate tables allocated once per thread, reused across responses.
var gzipOut {.threadvar.}: Output
  ## Reusable compressed-output buffer (reset per response/turn).

func findRespHeader(res: HttpResponse, name: string): int =
  ## Index of a response header (case-insensitive key), or -1.
  for i in 0 ..< res.headers.len:
    if cmpIgnoreCase(res.headers[i][0], name) == 0:
      return i
  -1

proc gzipEncodeBody(res: HttpResponse, bodyPtr: pointer, bodyLen: int;
                    connCtx: ConnHttp): tuple[p: pointer, len: int] =
  ## Gzip `bodyLen` bytes at `bodyPtr` into the thread-local output when all
  ## gates pass; otherwise (nil, 0) — serve identity. Gates: enabled-or-armed,
  ## client accepts, size, present-and-compressible Content-Type, no existing
  ## Content-Encoding, output actually smaller. The returned pointer borrows
  ## the thread-local buffer: consume it before the next compression call.
  result = (nil, 0)
  if bodyLen <= 0 or bodyPtr == nil:
    return
  if not (res.server.compressEnabled or res.compressArmed):
    return
  if bodyLen < res.server.compressMinLen:
    return
  if connCtx == nil:
    return
  if not connCtx.acceptsGzip:
    # Server flag was off at dispatch, so nothing was precomputed — but this
    # response is explicitly armed: parse now. The parser lives for the whole
    # dispatch, and HEAD is excluded here just like at dispatch.
    if not res.compressArmed or connCtx.parser == nil:
      return
    if connCtx.parser.methodCache == HttpHead:
      return
    if not parseAcceptsGzip(connCtx.parser.getHeaderValue("accept-encoding")):
      return
  if findRespHeader(res, "content-encoding") >= 0:
    return
  let ci = findRespHeader(res, "content-type")
  if ci < 0:
    return # unknown type: skip (never spend deflate on a guess)
  var compressible = false
  {.cast(gcsafe).}:
    # Double-checked locking inside; read-only after init.
    compressible = isCompressibleType(res.headers[ci][1])
  if not compressible:
    return
  if gzipOut == nil:
    gzipOut = newOutput(bodyLen + 64)
  else:
    reset(gzipOut)
  openGzipStream(gzipStrm, gzipOut, res.server.compressLevel)
  writeGzip(gzipStrm, bodyPtr, bodyLen)
  finishGzip(gzipStrm)
  let sp = outputBytes(gzipOut)
  if sp.len <= 0 or sp.len >= bodyLen:
    return # incompressible: serve identity
  result = (sp.p, sp.len)

proc gzipVaryValue(res: HttpResponse): string =
  ## Vary value for a compressed response: "Accept-Encoding" merged with an
  ## app-set Vary, or "" when the app value already covers it (emit nothing).
  let vi = findRespHeader(res, "vary")
  if vi < 0:
    return "Accept-Encoding"
  let cur = res.headers[vi][1]
  if "accept-encoding" in cur.toLowerAscii():
    return ""
  cur & ", Accept-Encoding"


var fileReadPool {.threadvar.}: PooledBuffer[byte]
  ## Reusable file-read chunks for the compressed sendFile path (and any
  ## future buffered file pump). Backing allocated once per thread.

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
  let connCtx = if res.conn.data != nil: cast[ConnHttp](res.conn.data) else: nil
  # Compression attempt: on success the wire body/length swap to the
  # thread-local gzip output and Content-Encoding (+ merged Vary) are
  # emitted below. Identity path is byte-identical to before.
  let (compPtr, compLen) = gzipEncodeBody(res, bodyPtr, bodyLen, connCtx)
  let comp = compPtr != nil
  var eBodyLen = if comp: compLen else: bodyLen
  var eBodyPtr = if comp: compPtr else: bodyPtr
  # Merged Vary for the compressed mode ("" = app value already covers it).
  # skipVaryIdx re-emits it merged; an app Content-Length is dropped when
  # compressing (it describes the identity body, not the wire bytes).
  var varyVal = ""
  var skipVaryIdx = -1
  if comp:
    varyVal = gzipVaryValue(res)
    if varyVal.len > 0:
      skipVaryIdx = findRespHeader(res, "vary")
  # Extra header bytes in compressed mode: "Content-Encoding: gzip\r\n" (24)
  # plus optional "Vary: <v>\r\n".
  let compExtra = if comp: 24 + (if varyVal.len > 0: 6 + varyVal.len + 2 else: 0) else: 0

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
  p += writeUint(cast[ptr UncheckedArray[byte]](addr buf[p]), eBodyLen)
  copyMem(addr buf[p], "\r\n".cstring, 2); p += 2

  copyMem(addr buf[p], "Connection: ".cstring, 12); p += 12
  copyMem(addr buf[p], connHeader.cstring, connHeader.len); p += connHeader.len
  copyMem(addr buf[p], "\r\n".cstring, 2); p += 2
  # Fixed part is <= ~144 bytes (longest reason phrase is 30 chars), so it
  # always fits the 1024-byte buffer; only custom headers + body can overflow.
  let fixedEnd = p

  let tailReserve = 2 + eBodyLen + compExtra  # final CRLF + body + extras
  # Account for the tail up front: with zero custom headers the loop below
  # never runs, so starting from `true` would wrongly take the fast path and
  # overflow the 1024-byte stack buffer with a large body.
  var fit = p + tailReserve <= FastSingleWriteCap
  for i in 0 ..< res.headers.len:
    let k = res.headers[i][0]
    let v = res.headers[i][1]
    if comp:
      if i == skipVaryIdx:
        continue # re-emitted merged below
      if cmpIgnoreCase(k, "content-length") == 0:
        continue # identity length is wrong for the compressed body
    # Reserve space for this header plus everything that still follows it,
    # so a successful loop guarantees the tail fits without re-checking.
    if p + k.len + v.len + 4 + tailReserve > FastSingleWriteCap:
      fit = false
      break
    copyMem(addr buf[p], k.cstring, k.len); p += k.len
    copyMem(addr buf[p], ": ".cstring, 2); p += 2
    copyMem(addr buf[p], v.cstring, v.len); p += v.len
    copyMem(addr buf[p], "\r\n".cstring, 2); p += 2

  if comp:
    copyMem(addr buf[p], "Content-Encoding: gzip\r\n".cstring, 24); p += 24
    if varyVal.len > 0:
      copyMem(addr buf[p], "Vary: ".cstring, 6); p += 6
      copyMem(addr buf[p], varyVal.cstring, varyVal.len); p += varyVal.len
      copyMem(addr buf[p], "\r\n".cstring, 2); p += 2

  if fit:
    # Fast path: everything coalesced in one stack buffer, one send().
    copyMem(addr buf[p], "\r\n".cstring, 2); p += 2
    if eBodyLen > 0:
      copyMem(addr buf[p], eBodyPtr, eBodyLen); p += eBodyLen
    discard res.conn.send(buf.toOpenArray(0, p - 1))
  else:
    type Part = tuple[data: ptr UncheckedArray[byte], len: int]
    const MaxParts = 150
    let numParts = 1 + res.headers.len * 4 + 1 + (if eBodyLen > 0: 1 else: 0) +
      (if comp: 8 else: 0)

    template scatterWrite(parts: var openArray[Part], count: var int) =
      # First part is the fixed headers only (custom headers that fit were
      # appended past fixedEnd but are re-emitted below, so stop before them).
      parts[count] = (cast[ptr UncheckedArray[byte]](addr buf[0]), fixedEnd); inc count
      for i in 0 ..< res.headers.len:
        let k = res.headers[i][0]
        let v = res.headers[i][1]
        if comp:
          if i == skipVaryIdx:
            continue # re-emitted merged below
          if cmpIgnoreCase(k, "content-length") == 0:
            continue
        parts[count] = (cast[ptr UncheckedArray[byte]](k.cstring), k.len); inc count
        parts[count] = (cast[ptr UncheckedArray[byte]](": ".cstring), 2); inc count
        parts[count] = (cast[ptr UncheckedArray[byte]](v.cstring), v.len); inc count
        parts[count] = (cast[ptr UncheckedArray[byte]]("\r\n".cstring), 2); inc count
      if comp:
        parts[count] = (cast[ptr UncheckedArray[byte]]("Content-Encoding".cstring), 16); inc count
        parts[count] = (cast[ptr UncheckedArray[byte]](": ".cstring), 2); inc count
        parts[count] = (cast[ptr UncheckedArray[byte]]("gzip".cstring), 4); inc count
        parts[count] = (cast[ptr UncheckedArray[byte]]("\r\n".cstring), 2); inc count
        if varyVal.len > 0:
          parts[count] = (cast[ptr UncheckedArray[byte]]("Vary".cstring), 4); inc count
          parts[count] = (cast[ptr UncheckedArray[byte]](": ".cstring), 2); inc count
          parts[count] = (cast[ptr UncheckedArray[byte]](varyVal.cstring), varyVal.len); inc count
          parts[count] = (cast[ptr UncheckedArray[byte]]("\r\n".cstring), 2); inc count
      parts[count] = (cast[ptr UncheckedArray[byte]]("\r\n".cstring), 2); inc count
      if eBodyLen > 0:
        parts[count] = (cast[ptr UncheckedArray[byte]](eBodyPtr), eBodyLen); inc count

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

proc compress*(res: HttpResponse, body: string = "") =
  ## Compressing send: arms gzip for this response, then sends. Identical to
  ## `send()` when `server.compressEnabled` is on; forces the attempt for one
  ## response when off. Falls back to identity whenever any gate fails
  ## (no Accept-Encoding, small/unknown/incompressible type, HEAD, ...).
  if res.sent: return
  res.compressArmed = true
  res.send(body)

proc compress*(res: HttpResponse, body: seq[byte]) =
  ## `seq[byte]` variant of `compress`.
  if res.sent: return
  res.compressArmed = true
  res.send(body)

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

    # Compressed file path: stream read → gzip → chunked, entirely through
    # thread-local reused buffers (bounded memory at any file size). Range +
    # compression never mix: a satisfiable Range takes the identity 206 path
    # below. Falls out of the block to identity whenever any gate fails.
    block compressFile:
      let srv = res.server
      if not srv.compressEnabled:
        break compressFile
      if status != Http200 or rangeLen < srv.compressMinLen:
        break compressFile
      if req != default(HttpRequest) and req.httpMethod == HttpHead:
        break compressFile
      let connCtx = if res.conn.data != nil: cast[ConnHttp](res.conn.data) else: nil
      if connCtx == nil or not connCtx.acceptsGzip:
        break compressFile
      if findRespHeader(res, "content-encoding") >= 0:
        break compressFile
      var fileCompressible = false
      {.cast(gcsafe).}:
        # Double-checked locking inside; read-only after init.
        fileCompressible = isCompressibleExt(getFileExt(path))
      if not fileCompressible:
        break compressFile
      let mimeType = if isExtension(getFileExt(path)): getMimeType(getFileExt(path)).get()
                     else: "application/octet-stream"
      # Head: chunked + gzip. No Content-Length (identity length would be
      # wrong), no Accept-Ranges (ranges address the identity body).
      var hdrBuf = res.bodyBytes
      var hp = 0
      hdrAdd(hdrBuf, hp, "HTTP/1.1 200 OK\r\n", 17)
      hdrDate(hdrBuf, hp)
      hdrAdd(hdrBuf, hp, "Transfer-Encoding: chunked\r\n", 28)
      hdrAdd(hdrBuf, hp, "Content-Type: ", 14)
      hdrAdd(hdrBuf, hp, mimeType)
      hdrAdd(hdrBuf, hp, "\r\n", 2)
      hdrAdd(hdrBuf, hp, "Content-Encoding: gzip\r\n", 24)
      let vv = gzipVaryValue(res)
      var skipVary = -1
      if vv.len > 0:
        hdrAdd(hdrBuf, hp, "Vary: ", 6)
        hdrAdd(hdrBuf, hp, vv)
        hdrAdd(hdrBuf, hp, "\r\n", 2)
        skipVary = findRespHeader(res, "vary")
      if contentDisposition:
        let (_, fileName, _) = path.splitFile()
        hdrEnsure(hdrBuf, hp, 43 + fileName.len + 3)
        writeDisposition(cast[ptr UncheckedArray[byte]](addr hdrBuf[0]), fileName, hp)
      hdrAdd(hdrBuf, hp, "Connection: ", 12)
      hdrAdd(hdrBuf, hp, connHeader)
      hdrAdd(hdrBuf, hp, "\r\n", 2)
      for i in 0 ..< res.headers.len:
        if i == skipVary:
          continue # re-emitted merged above
        if cmpIgnoreCase(res.headers[i][0], "content-length") == 0:
          continue # identity length is wrong for the compressed body
        hdrAdd(hdrBuf, hp, res.headers[i][0])
        hdrAdd(hdrBuf, hp, ": ", 2)
        hdrAdd(hdrBuf, hp, res.headers[i][1])
        hdrAdd(hdrBuf, hp, "\r\n", 2)
      hdrAdd(hdrBuf, hp, "\r\n", 2)
      type CPart = tuple[data: ptr UncheckedArray[byte]; len: int]
      var cparts {.noinit.}: array[1, CPart]
      var ccount = 0
      cparts[ccount] = (cast[ptr UncheckedArray[byte]](addr hdrBuf[0]), hp); inc ccount
      discard res.conn.sendv(cparts.toOpenArray(0, ccount - 1))
      # Stream turns: 64 KiB in, compressed bytes out as one chunk each.
      const FileChunk = 65536
      ensureCap(fileReadPool, FileChunk)
      if gzipOut == nil:
        gzipOut = newOutput(FileChunk + 128)
      else:
        reset(gzipOut)
      openGzipStream(gzipStrm, gzipOut, srv.compressLevel)
      discard seekFile(fileFd, rangeStart)
      var remain = rangeLen
      var ok = true
      while remain > 0:
        if res.conn.state != Connected:
          ok = false
          break
        let toRead = if remain > FileChunk: FileChunk else: int(remain)
        let n = readFile(fileFd,
          cast[ptr UncheckedArray[byte]](addr fileReadPool.data[0]), toRead)
        if n <= 0:
          ok = false
          break
        writeGzip(gzipStrm, fileReadPool.data.toOpenArray(0, n - 1))
        let sp = outputBytes(gzipOut)
        if sp.len > 0:
          sendRawChunk(res.conn, sp.p, sp.len)
          reset(gzipOut)
        remain -= n
      if ok:
        finishGzip(gzipStrm)
        let fsp = outputBytes(gzipOut)
        if fsp.len > 0:
          sendRawChunk(res.conn, fsp.p, fsp.len)
        discard res.conn.send("0\r\n\r\n")
      closeFile(fileFd)
      if res.closeConn:
        when defined(windows):
          res.conn.closeAfterSend()
        else:
          res.conn.closeAfterDrain()
      return

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
        when defined(windows):
          # RST (closeAfterDrain's SO_LINGER=0 fast path) discards the
          # peer's unread receive buffer on Windows, truncating just-sent
          # file bytes. Use the FIN fast path like plain send() does.
          res.conn.closeAfterSend()
        else:
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
        when defined(windows):
          # RST (closeAfterDrain's SO_LINGER=0 fast path) discards the
          # peer's unread receive buffer on Windows, truncating just-sent
          # file bytes. Use the FIN fast path like plain send() does.
          res.conn.closeAfterSend()
        else:
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
      when defined(windows):
        # RST (closeAfterDrain's SO_LINGER=0 fast path) discards the
        # peer's unread receive buffer on Windows, truncating just-sent
        # file bytes. Use the FIN fast path like plain send() does.
        res.conn.closeAfterSend()
      else:
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

# ── Session teardown (forward declarations) ───────────────────────────────────

proc removeSession*(server: HttpServer, conn: Connection)
  ## Detach `conn` from session tracking and recycle its state (defined
  ## below, next to markIdle). Declared early for SseStream.close/drain.
proc closeStale(server: HttpServer, ctx: ConnHttp)
  ## Shut an idle/stalled session (defined below, next to the sweep).
proc maybeDrained(server: HttpServer) {.gcsafe.}
  ## Fire the drain callback once the last session is gone (defined below).

# ── Chunked / SSE streaming ───────────────────────────────────────────────────

type
  SseStream* = ref object
    ## An open chunked response stream (`Transfer-Encoding: chunked`).
    ## Created by `startChunked` / `startSse`; survives the handler return so
    ## events can be pushed later from timers or other callbacks. The owning
    ## `HttpResponse` is pooled on dispatch return — keep only this handle.
    ## While open, the connection is owned by the stream: the timeout sweep
    ## applies `readTimeoutMs` from the last chunk, so send a heartbeat
    ## (`sendComment`) more often than that when events are sparse.
    conn: Connection
    server: HttpServer
    closeAfter: bool    ## from res.closeConn at start: FIN after terminator
    closed: bool

var ssePool {.threadvar.}: PooledBuffer[byte]
  ## Reused framing buffer for multi-line SSE events (slow path).
  ## Allocated once per thread via `initPool`, then flat: steady-state
  ## multi-line sends copy into it with no heap traffic.



func chunkSizeHex(n: int): string =
  ## Lowercase hex without leading zeros for chunk-size lines.
  if n == 0:
    return "0"
  var v = n
  var digits {.noinit.}: array[16, char]
  var len = 0
  while v > 0:
    let d = v and 0xF
    digits[len] = if d < 10: char(ord('0') + d) else: char(ord('a') + d - 10)
    inc len
    v = v shr 4
  result = newString(len)
  for i in 0 ..< len:
    result[i] = digits[len - 1 - i]

template touchStream(s: SseStream) =
  ## Restart the read-timeout window from this chunk.
  if s.conn.data != nil:
    let c = cast[ConnHttp](s.conn.data)
    if c != nil:
      c.lastActive = if pollNowMs != 0: pollNowMs else: monoMs()

proc startChunked*(res: HttpResponse, contentType: string): SseStream =
  ## Send the response headers with `Transfer-Encoding: chunked` and return
  ## a stream for incremental writes. Uses `res.statusCode` and any headers
  ## set via `res.header()` before the call. Marks the response sent; further
  ## `send`/`sendFile` calls on `res` are no-ops — write via the stream.
  ## `Connection: keep-alive` is forced unless `res.close()` was called, in
  ## which case the connection FINs after the stream terminator.
  if res.sent:
    return nil
  res.sent = true
  let s = SseStream(conn: res.conn, server: res.server,
                    closeAfter: res.closeConn, closed: false)
  buffaloScope:
    var hb {.buffalo.}: StaticBuffer[byte, 2048]
    try:
      # Zero-alloc head: status line + headers built into stack scratch,
      # sent as one view. Falls back to the heap path below past 2 KiB.
      hb.appendMany("HTTP/1.1 ")
      let sc = res.statusCode.int
      hb.add(byte(ord('0') + sc div 100))
      hb.add(byte(ord('0') + (sc div 10) mod 10))
      hb.add(byte(ord('0') + sc mod 10))
      hb.add(byte(' '))
      hb.appendMany(statusText(HttpCode(res.statusCode)))
      hb.appendMany("\r\nDate: ")
      hb.appendMany(cachedHttpDate())
      hb.appendMany("\r\nContent-Type: ")
      hb.appendMany(contentType)
      hb.appendMany("\r\nTransfer-Encoding: chunked\r\nConnection: ")
      hb.appendMany(if res.closeConn: "close" else: "keep-alive")
      hb.appendMany("\r\n")
      for (k, v) in res.headers:
        hb.appendMany(k)
        hb.appendMany(": ")
        hb.appendMany(v)
        hb.appendMany("\r\n")
      hb.appendMany("\r\n")
      discard res.conn.send(hb.toOpenArray())
    except RangeDefect:
      # Absurdly large header block (cold): heap fallback.
      var head = "HTTP/1.1 " & $res.statusCode.int & " " &
                 statusText(HttpCode(res.statusCode)) & "\r\n" &
                 "Date: " & cachedHttpDate() & "\r\n" &
                 "Content-Type: " & contentType & "\r\n" &
                 "Transfer-Encoding: chunked\r\n" &
                 "Connection: " & (if res.closeConn: "close" else: "keep-alive") & "\r\n"
      for (k, v) in res.headers:
        head.add(k & ": " & v & "\r\n")
      head.add("\r\n")
      discard res.conn.send(head)
  if res.conn.data != nil:
    let ctx = cast[ConnHttp](res.conn.data)
    if ctx != nil:
      ctx.streamingResponse = true
  s.touchStream()
  s

proc startSse*(res: HttpResponse): SseStream =
  ## Start a `text/event-stream` response (see `startChunked`). Adds
  ## `Cache-Control: no-cache` and the `X-Accel-Buffering: no` proxy hint.
  discard res.header("Cache-Control", "no-cache")
  discard res.header("X-Accel-Buffering", "no")
  res.startChunked("text/event-stream")

proc isClosed*(s: SseStream): bool {.inline.} =
  ## True once `close` ran or the connection died.
  s == nil or s.closed

proc writeChunk*(s: SseStream, data: openArray[byte]) =
  ## Write one raw chunk. Empty payloads are skipped (use `sendComment`
  ## for heartbeats). Dead connections mark the stream closed.
  ## Zero-alloc: the frame scatters (`chunk-size CRLF payload CRLF`) via
  ## `sendv` — the payload is never copied.
  if s == nil or s.closed:
    return
  if s.conn.state != Connected:
    s.closed = true
    return
  if data.len == 0:
    return
  var hexBuf: array[18, byte]
  let hxLen = chunkHexInto(hexBuf, data.len)
  hexBuf[hxLen] = byte('\r')
  hexBuf[hxLen + 1] = byte('\n')
  var tail: array[2, byte] = [byte('\r'), byte('\n')]
  var parts: array[4, tuple[data: ptr UncheckedArray[byte], len: int]]
  parts[0] = (cast[ptr UncheckedArray[byte]](addr hexBuf[0]), hxLen + 2)
  parts[1] = (cast[ptr UncheckedArray[byte]](unsafeAddr data[0]), data.len)
  parts[2] = (cast[ptr UncheckedArray[byte]](addr tail[0]), 2)
  # parts[3] unused: 3-element scatter (header+payload+trailer).
  discard s.conn.sendv(parts.toOpenArray(0, 2))
  s.touchStream()

proc writeChunk*(s: SseStream, data: string) {.inline.} =
  ## String variant of `writeChunk`.
  if data.len > 0:
    s.writeChunk(data.toOpenArrayByte(0, data.high))

proc sendEvent*(s: SseStream, data: openArray[byte],
                event: openArray[char] = [], id: openArray[char] = [],
                retry = 0) =
  ## Send one SSE message as a single chunk. Single-line payloads (the
  ## common case) scatter straight from the caller's memory via `sendv`:
  ## no framing copy, no heap allocation. Multi-line payloads take the
  ## pooled-buffer slow path (one copy into reused thread-local storage,
  ## still no allocation after warmup).
  if s == nil or s.closed:
    return
  if s.conn.state != Connected:
    s.closed = true
    return
  var multiline = false
  for b in data:
    if b == byte('\n'):
      multiline = true
      break
  if multiline:
    if ssePool.cap == 0:
      ssePool = initPool(byte, 8192)
    withBorrow(ssePool, buf):
      if id.len > 0:
        buf.appendMany("id: ")
        for ch in id:
          if ch != '\r' and ch != '\n':
            buf.add(byte(ch))
        buf.add(byte('\n'))
      if event.len > 0:
        buf.appendMany("event: ")
        for ch in event:
          if ch != '\r' and ch != '\n':
            buf.add(byte(ch))
        buf.add(byte('\n'))
      if data.len == 0:
        buf.appendMany("data: \n")
      else:
        buf.appendMany("data: ")
        for i in 0 ..< data.len:
          let b = data[i]
          if b == byte('\n'):
            if buf.len > 0 and buf[buf.len - 1] == byte('\r'):
              discard buf.pop()
            buf.add(byte('\n'))
            if i + 1 < data.len:
              buf.appendMany("data: ")
          elif b == byte('\r'):
            buf.add(b)
          else:
            buf.add(b)
        if data[^1] != byte('\n'):
          if buf[buf.len - 1] == byte('\r'):
            discard buf.pop()
          buf.add(byte('\n'))
      if retry > 0:
        buf.appendMany("retry: ")
        var digits: array[20, byte]
        var nd = 0
        var v = retry
        while v > 0:
          digits[nd] = byte(ord('0') + v mod 10)
          inc nd
          v = v div 10
        for i in countdown(nd - 1, 0):
          buf.add(digits[i])
        buf.add(byte('\n'))
      buf.add(byte('\n'))
      s.writeChunk(buf.toOpenArray())
    return
  # Fast path: frame length is known without building the frame.
  var framed = 0
  if id.len > 0:
    framed += 4 + id.len + 1
  if event.len > 0:
    framed += 7 + event.len + 1
  framed += 6 + data.len + 1
  var retryBuf: array[32, byte]
  var retryLen = 0
  if retry > 0:
    var digits: array[20, byte]
    var nd = 0
    var v = retry
    while v > 0:
      digits[nd] = byte(ord('0') + v mod 10)
      inc nd
      v = v div 10
    retryBuf[0] = byte('r'); retryBuf[1] = byte('e')
    retryBuf[2] = byte('t'); retryBuf[3] = byte('r')
    retryBuf[4] = byte('y'); retryBuf[5] = byte(':')
    retryBuf[6] = byte(' ')
    for i in countdown(nd - 1, 0):
      retryBuf[7 + (nd - 1 - i)] = digits[i]
    retryBuf[7 + nd] = byte('\n')
    retryLen = 8 + nd
    framed += retryLen
  framed += 1 # trailing blank line
  var headBuf: array[18, byte]
  let headLen = chunkHexInto(headBuf, framed)
  headBuf[headLen] = byte('\r')
  headBuf[headLen + 1] = byte('\n')
  let headTotal = headLen + 2
  # Fixed wire words live in one stack table (no heap, stable address).
  var words: array[27, byte] = [
    byte('i'), byte('d'), byte(':'), byte(' '),
    byte('e'), byte('v'), byte('e'), byte('n'), byte('t'), byte(':'), byte(' '),
    byte('d'), byte('a'), byte('t'), byte('a'), byte(':'), byte(' '),
    byte('\n'), byte('\r'), byte('\n'),
    byte('r'), byte('e'), byte('t'), byte('r'), byte('y'), byte(':'), byte(' ')]
  let w = cast[ptr UncheckedArray[byte]](addr words[0])
  var parts: array[13, tuple[data: ptr UncheckedArray[byte], len: int]]
  var n = 0
  parts[n] = (cast[ptr UncheckedArray[byte]](addr headBuf[0]), headTotal); inc n
  if id.len > 0:
    parts[n] = (w, 4); inc n
    parts[n] = (cast[ptr UncheckedArray[byte]](unsafeAddr id[0]), id.len); inc n
    parts[n] = (cast[ptr UncheckedArray[byte]](addr words[17]), 1); inc n
  if event.len > 0:
    parts[n] = (cast[ptr UncheckedArray[byte]](addr words[4]), 7); inc n
    parts[n] = (cast[ptr UncheckedArray[byte]](unsafeAddr event[0]), event.len); inc n
    parts[n] = (cast[ptr UncheckedArray[byte]](addr words[17]), 1); inc n
  parts[n] = (cast[ptr UncheckedArray[byte]](addr words[11]), 6); inc n
  if data.len > 0:
    parts[n] = (cast[ptr UncheckedArray[byte]](unsafeAddr data[0]), data.len); inc n
  parts[n] = (cast[ptr UncheckedArray[byte]](addr words[17]), 1); inc n
  if retryLen > 0:
    parts[n] = (cast[ptr UncheckedArray[byte]](addr retryBuf[0]), retryLen); inc n
  parts[n] = (cast[ptr UncheckedArray[byte]](addr words[17]), 1); inc n
  parts[n] = (cast[ptr UncheckedArray[byte]](addr words[18]), 2); inc n
  discard s.conn.sendv(parts.toOpenArray(0, n - 1))
  s.touchStream()

proc sendEvent*(s: SseStream, data: string, event = "", id = "",
                retry = 0) {.inline.} =
  ## String wrapper: views the input, no copy before framing.
  if s == nil or s.closed:
    return
  if data.len == 0:
    s.sendEvent([], event.toOpenArray(0, event.high),
                id.toOpenArray(0, id.high), retry)
  else:
    s.sendEvent(data.toOpenArrayByte(0, data.high),
                event.toOpenArray(0, event.high),
                id.toOpenArray(0, id.high), retry)

proc sendComment*(s: SseStream, comment: openArray[char] = []) =
  ## Send an SSE heartbeat (`: comment`) — no event is dispatched.
  ## Call more often than `readTimeoutMs` when events are sparse.
  ## Zero-alloc like `sendEvent`: single-line comments scatter, multi-line
  ## comments use the pooled slow path.
  if s == nil or s.closed:
    return
  if s.conn.state != Connected:
    s.closed = true
    return
  var multiline = false
  for ch in comment:
    if ch == '\n':
      multiline = true
      break
  if multiline:
    if ssePool.cap == 0:
      ssePool = initPool(byte, 8192)
    withBorrow(ssePool, buf):
      buf.appendMany(": ")
      for i in 0 ..< comment.len:
        let ch = comment[i]
        if ch == '\n':
          if buf.len > 0 and buf[buf.len - 1] == byte('\r'):
            discard buf.pop()
          buf.add(byte('\n'))
          if i + 1 < comment.len:
            buf.appendMany(": ")
        elif ch != '\r':
          buf.add(byte(ch))
      if comment[^1] != '\n':
        if buf[buf.len - 1] == byte('\r'):
          discard buf.pop()
        buf.add(byte('\n'))
      buf.add(byte('\n'))
      s.writeChunk(buf.toOpenArray())
    return
  var headBuf: array[18, byte]
  var framed: int
  var payOff = 0
  if comment.len == 0:
    framed = 3 # ":\n\n"
  else:
    framed = 2 + comment.len + 1 + 1 # ": " + comment + "\n" + "\n"
  let headLen = chunkHexInto(headBuf, framed)
  headBuf[headLen] = byte('\r')
  headBuf[headLen + 1] = byte('\n')
  var parts: array[6, tuple[data: ptr UncheckedArray[byte], len: int]]
  var n = 0
  parts[n] = (cast[ptr UncheckedArray[byte]](addr headBuf[0]), headLen + 2); inc n
  if comment.len == 0:
    var colon: array[1, byte] = [byte(':')]
    parts[n] = (cast[ptr UncheckedArray[byte]](addr colon[0]), 1); inc n
  else:
    var pfx: array[2, byte] = [byte(':'), byte(' ')]
    parts[n] = (cast[ptr UncheckedArray[byte]](addr pfx[0]), 2); inc n
    parts[n] = (cast[ptr UncheckedArray[byte]](unsafeAddr comment[0]), comment.len); inc n
  var nl: array[1, byte] = [byte('\n')]
  parts[n] = (cast[ptr UncheckedArray[byte]](addr nl[0]), 1); inc n
  parts[n] = (cast[ptr UncheckedArray[byte]](addr nl[0]), 1); inc n
  var tail: array[2, byte] = [byte('\r'), byte('\n')]
  parts[n] = (cast[ptr UncheckedArray[byte]](addr tail[0]), 2); inc n
  discard s.conn.sendv(parts.toOpenArray(0, n - 1))
  s.touchStream()

proc close*(s: SseStream, trailers: openArray[(string, string)] = []) =
  ## Terminate the stream (`0`-chunk, optional trailers) and release the
  ## connection back to keep-alive (or FIN when `res.close()` was set at
  ## start). Idempotent; safe to call from any loop callback.
  if s == nil or s.closed:
    return
  s.closed = true
  if s.conn.state == Connected:
    if trailers.len == 0:
      discard s.conn.send("0\r\n\r\n")
    else:
      var tail = "0\r\n"
      for (k, v) in trailers:
        tail.add(k & ": " & v & "\r\n")
      tail.add("\r\n")
      discard s.conn.send(tail)
    if s.conn.data != nil:
      let ctx = cast[ConnHttp](s.conn.data)
      if ctx != nil:
        ctx.streamingResponse = false
        let now = if pollNowMs != 0: pollNowMs else: monoMs()
        ctx.lastActive = now
        ctx.idleAfter = now
    if s.server.draining:
      # Graceful shutdown: don't park keep-alive — tear down after the
      # terminator flushes. removeSession fires maybeDrained. Runs on the
      # loop thread like every other session teardown, hence the cast.
      let c = s.conn
      {.cast(gcsafe).}:
        s.server.removeSession(c)
      when defined(windows):
        # RST (closeAfterDrain's SO_LINGER=0 fast path) discards the
        # peer's unread receive buffer on Windows, truncating the just-sent
        # terminator. Use the FIN fast path like the file-send sites do.
        c.closeAfterSend()
      else:
        c.closeAfterDrain()
    elif s.closeAfter:
      s.conn.closeAfterSend()

# ── HttpResponse pooling ──────────────────────────────────────────────────────────

proc acquireHttpResponse(server: HttpServer, conn: Connection): HttpResponse =
  if server.resPool.len > 0:
    result = server.resPool.pop()
    result.conn = conn
    result.server = server
    result.headers.setLen(0)
    result.bodyBytes.setLen(0)
    result.compressArmed = false
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

type
  HttpServerOptions* = object
    ## Operator-tunable runtime knobs for `HttpServer`. Zero values mean
    ## "unlimited/disabled" exactly as on the server fields, except
    ## `keepAliveMs`, `readTimeoutMs` and `timeoutSweepMs` — start from
    ## `defaultHttpServerOptions()` to keep the powpow defaults there.
    maxBodySize*, maxStreamBodySize*: int64
      ## Total request-body caps (bytes).
    maxFileSize*, maxFieldSize*: int64
      ## Per-file / per-text-field multipart caps (bytes).
    maxConnections*, maxPipelineDepth*: int
    readTimeoutMs*, wsIdleTimeoutMs*, timeoutSweepMs*, keepAliveMs*: int
      ## Millisecond timeouts. `keepAliveMs = 0` disables idle close.

proc defaultHttpServerOptions*(): HttpServerOptions =
  ## `HttpServerOptions` matching the `newHttpServer` constructor defaults.
  HttpServerOptions(
    readTimeoutMs: DefaultReadTimeoutMs,
    timeoutSweepMs: DefaultTimeoutSweepMs,
    keepAliveMs: DefaultKeepAliveMs
  )

proc populatePools*(server: HttpServer; poolSize = 256)

proc newHttpServer*(loop: Loop; populate: bool = true): HttpServer =
  ## Create an HTTP server on the given event loop. Pools (parsers,
  ## responses, connections, read buffers) are prewarmed by default so the
  ## request hot path performs no allocations; pass `populate = false` to
  ## defer ~1 MB of startup allocations.
  let srv = HttpServer(
    tcpServers: @[],
    loop:      loop,
    ownsLoop:  false,
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
    compressEnabled: false,
    compressMinLen: 1024,
    compressLevel: 6,
    proxyProtocol: false,
    wsIdleTimeoutMs: 0,
    timeoutSweepMs: 200,
    sweepTimer: TimerId(0)
  )
  if populate:
    srv.populatePools()
  srv

proc newHttpServer*(populate: bool = true): HttpServer =
  ## Create an HTTP server with its own internal event loop.
  ## `run`/`start` drive it; `close` frees it. Use `getLoop`
  ## to share the loop with other subsystems.
  var eventLoop = newLoop()
  try:
    result = newHttpServer(eventLoop, populate)
    result.ownsLoop = true
  except CatchableError:
    eventLoop.close()
    raise

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
  ## Stop the HTTP server (use from a callback). Frees an owned loop
  ## via `close` semantics once `run` returns; a borrowed loop is
  ## stopped but left alive for its owner.
  if server == nil: return
  server.close()
  if not server.ownsLoop and server.loop != nil and
      not server.loop.closed and server.loop.isRunning():
    server.loop.stop()

proc drain*(server: HttpServer, timeoutMs = 30_000,
            onDrained: DrainCallback = nil) =
  ## Graceful shutdown: close listeners (no new connections), shut idle
  ## keep-alive sessions now, and let in-flight requests and open
  ## chunked/SSE streams run to completion. When the last session closes,
  ## `onDrained` fires once on the loop thread — tear down there
  ## (`server.close()`). `timeoutMs` (0 = no deadline)
  ## force-closes whatever remains. Safe to call from any loop callback;
  ## idempotent while draining (a missing callback can still be attached).
  ##
  ## Teardown writes (queued response bytes, the SSE terminator) flush on
  ## subsequent polls — do NOT stop the loop inside `onDrained`, or the
  ## flush is truncated. Stop once clients observe close (or after a short
  ## grace timer).
  if server == nil: return
  if server.draining:
    if server.drainCb == nil and onDrained != nil:
      server.drainCb = onDrained
      server.maybeDrained()
    return
  server.draining = true
  server.drainCb = onDrained
  for ts in server.tcpServers:
    ts.close()
  # Idle sessions die now; in-flight ones finish through markIdle (which
  # closes instead of idling while draining), SseStream.close, or the
  # timeout sweep — every teardown funnels through removeSession, which
  # fires maybeDrained.
  server.sweepStale.setLen(0)
  for ctx in server.connRoots.values:
    if ctx.conn != nil and ctx.idleAfter >= ctx.lastActive:
      server.sweepStale.add(ctx)
  for ctx in server.sweepStale:
    server.closeStale(ctx)
  server.sweepStale.setLen(0)
  if server.connRoots.len == 0 and server.pendingConns.len == 0:
    server.maybeDrained()
    return
  if timeoutMs > 0:
    server.drainTimer = server.loop.addTimer(timeoutMs) do (id: int):
      # Stale fire (drain already settled and cleared drainCb): no-op.
      if server.drainCb == nil: return
      # Deadline expired: drop everything that is still open.
      server.sweepStale.setLen(0)
      for ctx in server.connRoots.values:
        server.sweepStale.add(ctx)
      for ctx in server.pendingConns:
        server.sweepStale.add(ctx)
      for ctx in server.sweepStale:
        if ctx.conn != nil:
          let c = ctx.conn
          server.removeSession(c)
          c.close()
      server.sweepStale.setLen(0)
      server.maybeDrained()

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

proc applyOptions*(server: HttpServer, opts: HttpServerOptions) =
  ## Applies `opts` to `server`, overwriting every knob literally.
  ## Start from `defaultHttpServerOptions()` and override individual
  ## fields to keep the powpow defaults for the rest.
  server.maxBodySize = opts.maxBodySize
  server.maxStreamBodySize = opts.maxStreamBodySize
  server.maxFileSize = opts.maxFileSize
  server.maxFieldSize = opts.maxFieldSize
  server.maxConnections = opts.maxConnections
  server.maxPipelineDepth = opts.maxPipelineDepth
  server.readTimeoutMs = opts.readTimeoutMs
  server.wsIdleTimeoutMs = opts.wsIdleTimeoutMs
  server.timeoutSweepMs = opts.timeoutSweepMs
  server.setKeepAliveTimeout(opts.keepAliveMs)

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
    result.proxyPending = server.proxyProtocol
    result.proxyBuf.setLen(0)
  else:
    result = ConnHttp(parser: acquireParser(server))
    result.conn = conn
    result.fd = conn.fd.int
    result.lastActive = monoMs()
    result.proxyPending = server.proxyProtocol
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
  ctx.streamingResponse = false
  ctx.acceptsGzip = false
  ctx.proxyPending = false
  ctx.proxyBuf.setLen(0)
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
  server.maybeDrained()

proc maybeDrained(server: HttpServer) {.gcsafe.} =
  ## Fire the drain callback once when no sessions remain. Called at the end
  ## of every session teardown, so any path that empties the server (request
  ## completion, stream close, timeout sweep, force-close) settles a drain.
  ## No timer cancel here (cancelTimer is not gcsafe-clean): a stale deadline
  ## that fires later is a guarded no-op via the drainCb check below.
  if not server.draining or server.drainCb == nil: return
  if server.connRoots.len == 0 and server.pendingConns.len == 0:
    server.drainTimer = TimerId(0)
    let cb = server.drainCb
    server.drainCb = nil
    server.draining = false
    # The callback is user code declared {.closure, gcsafe.} and always runs
    # on this loop thread (same contract as timer callbacks); the cast keeps
    # session teardown (removeSession) gcsafe-clean for upgrade/SSE paths.
    {.cast(gcsafe).}:
      cb()

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
  if server.draining:
    # Graceful shutdown: never park a connection idle — finish this request
    # and tear the session down. removeSession fires maybeDrained.
    server.removeSession(conn)
    when defined(windows):
      # Same Windows RST hazard as the SseStream drain path above: the FIN
      # fast path keeps the just-sent response deliverable.
      conn.closeAfterSend()
    else:
      conn.closeAfterDrain()
    return
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
  # Capture the peer IP up front: error/close responses may shut the socket
  # (fd = -1) before the entry below is built.
  let cip = conn.getClientIp()
  let started = if pollNowMs != 0: pollNowMs else: monoMs()
  let res = acquireHttpResponse(server, conn)
  if req.getConnectionClose():
    res.closeConn = true
  let ctx = if conn.data != nil: cast[ConnHttp](conn.data) else: nil
  if ctx != nil:
    ctx.acceptsGzip = server.compressEnabled and
      req.httpMethod != HttpHead and
      parseAcceptsGzip(req.getHeaderValue("accept-encoding"))
  if server.handler != nil:

    server.handler(req, res)
  else:
    res.sendError(Http500, "No handler configured")
  if server.onAccessLog != nil:
    let now = if pollNowMs != 0: pollNowMs else: monoMs()
    let ctx = if conn.data != nil: cast[ConnHttp](conn.data) else: nil
    server.onAccessLog(AccessLogEntry(
      clientIp: cip,
      httpMethod: req.httpMethod,
      path: $req.getPath(),
      statusCode: res.statusCode,
      durationMs: now - started,
      streaming: ctx != nil and ctx.streamingResponse))
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

# ── PROXY protocol ingress ──────────────────────────────────────────────────

proc rejectBadProxy(server: HttpServer, conn: Connection) =
  ## Fail closed on a malformed PROXY preface: 400 + close, never fed to
  ## the HTTP parser. Session cleanup runs on the close path as usual.
  let res = server.acquireHttpResponse(conn)
  res.sendError(Http400)
  server.releaseHttpResponse(res)

proc consumeProxyHeader(server: HttpServer, conn: Connection, ctx: ConnHttp,
                        data: openArray[byte]): tuple[done, inStash: bool;
                                                     consumed: int] =
  ## Consume the PROXY preface ahead of the HTTP parser. On `done` the caller
  ## feeds `[consumed..]` from the stash (`inStash`) or from `data`, then
  ## clears the stash. `done == false` = wait for more bytes, header-only
  ## read, or the 400 was already sent (return without feeding).
  if data.len == 0:
    return (false, false, 0)
  if ctx.proxyBuf.len == 0:
    # Fast path: the preface (≤232 valid bytes) almost always arrives with
    # the request head — parse in place, zero copy.
    let pr = parseProxyHeader(data)
    if pr.status == proxyNeedMore:
      if data.len > ProxyHoldCap:
        server.rejectBadProxy(conn)
        return (false, false, 0)
      for b in data:
        ctx.proxyBuf.add(b)
      return (false, false, 0) # possibly split: wait for the next read
    if pr.status == proxyBad:
      server.rejectBadProxy(conn)
      return (false, false, 0)
    if pr.status == proxyOk:
      conn.clientIp = pr.srcIp
    ctx.proxyPending = false
    if pr.consumed >= data.len:
      return (false, false, 0) # header only so far; the request follows
    return (true, false, pr.consumed)
  # Slow path: the preface was split across reads — accumulate (capped).
  if ctx.proxyBuf.len + data.len > ProxyHoldCap:
    ctx.proxyBuf.setLen(0)
    server.rejectBadProxy(conn)
    return (false, false, 0)
  for b in data:
    ctx.proxyBuf.add(b)
  let pr = parseProxyHeader(ctx.proxyBuf.toOpenArray(0, ctx.proxyBuf.high))
  if pr.status == proxyNeedMore:
    return (false, false, 0)
  if pr.status == proxyBad:
    ctx.proxyBuf.setLen(0)
    server.rejectBadProxy(conn)
    return (false, false, 0)
  if pr.status == proxyOk:
    conn.clientIp = pr.srcIp
  ctx.proxyPending = false
  if pr.consumed >= ctx.proxyBuf.len:
    ctx.proxyBuf.setLen(0)
    return (false, false, 0)
  (true, true, pr.consumed)

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
  var proxyInStash = false
  var proxyConsumed = 0
  if ctx.proxyPending:
    let pc = server.consumeProxyHeader(conn, ctx, data)
    if not pc.done:
      return # need more bytes, header-only read, or 400 already sent
    proxyInStash = pc.inStash
    proxyConsumed = pc.consumed
  try:
    if proxyInStash:
      p.feed(ctx.proxyBuf.toOpenArray(proxyConsumed, ctx.proxyBuf.high))
    elif proxyConsumed > 0:
      p.feed(data.toOpenArray(proxyConsumed, data.high))
    else:
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

  # Split-header PROXY remainder borrowed the stash: the synchronous feed is
  # done, release it (the fast path aliases the caller's buffer instead).
  if not ctx.proxyPending and ctx.proxyBuf.len > 0:
    ctx.proxyBuf.setLen(0)

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
    if conn.sendFileFd >= 0 or ctx.streamingResponse:
      # Response body still owned elsewhere (zero-copy send or an open
      # chunked/SSE stream): further pipelined bytes wait for the next read.
      break

  # All pipelined requests handled. If at least one request completed, the
  # connection is now idle waiting for the next one — the timeout sweep will
  # apply keepAliveMs. If the current request is still incomplete (slowloris),
  # it stays in the read-timeout state until readTimeoutMs. An open
  # chunked/SSE stream owns the connection instead: markIdle is deferred to
  # SseStream.close so the sweep keeps applying readTimeoutMs from the last
  # chunk rather than keepAliveMs from dispatch return.
  if conn.state == Connected and conn.data != nil and conn.sendFileFd < 0 and
     pipelineCount > 0 and not ctx.streamingResponse:
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
    # Capture the peer IP before sendError: the 4xx close tears the socket
    # down inline (fd = -1), after which getClientIp formats nothing.
    let cip = conn.getClientIp()
    let res = acquireHttpResponse(server, conn)
    res.sendError(errCode)
    if server.onAccessLog != nil:
      # Reject path: no dispatch, so log here (method/path best-effort —
      # empty when the request line never parsed).
      server.onAccessLog(AccessLogEntry(
        clientIp: cip,
        httpMethod: p.peekMethod(),
        path: $p.peekPath(),
        statusCode: uint16(ord(errCode)),
        durationMs: 0,
        streaming: false))
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

when not iouEnabled:
  proc adoptListenFd*(server: HttpServer, fd: SocketHandle) =
    ## Serve on an already-bound listen socket (see `createListenSocket`),
    ## adding one `TcpServer` per call just like `listen`. Intended for
    ## multi-worker servers, where a single listen socket is created once and
    ## adopted by every worker's loop; ownership stays with the creator, so
    ## `close()` never sockCloses it.
    ##
    ## Availability: the readiness backends only. `TcpServer.adoptListenFd`
    ## lives in the non-io_uring branch of `net/tcp.nim` because its only
    ## caller is `MultiThreadHttpServer`'s shared-listener path, which exists
    ## solely for Darwin — Linux and FreeBSD load-balance a SO_REUSEPORT group,
    ## but Darwin does not (there is no `SO_REUSEPORT_LB`), so there every
    ## worker would otherwise share one member and leave the rest idle.
    ## `iouEnabled` is Linux-only, so the two can never both hold and this
    ## gate removes no reachable code.
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
  ## Close the server and all active connections. When the server owns
  ## its loop (created via `newHttpServer()` without a loop), the loop
  ## is stopped (if running) or freed; a borrowed loop is left alive.
  if server == nil: return
  if server.loop != nil and not server.loop.closed:
    if server.sweepTimer != TimerId(0):
      server.loop.cancelTimer(server.sweepTimer)
      server.sweepTimer = TimerId(0)
    if server.drainTimer != TimerId(0):
      server.loop.cancelTimer(server.drainTimer)
      server.drainTimer = TimerId(0)
  else:
    server.sweepTimer = TimerId(0)
    server.drainTimer = TimerId(0)
  server.draining = false
  server.drainCb = nil
  for ts in server.tcpServers:
    ts.close()
  server.tcpServers.setLen(0)
  server.connRoots.clear()
  server.pendingConns.setLen(0)
  server.parserPool.setLen(0)
  if server.ownsLoop and server.loop != nil and not server.loop.closed:
    if server.loop.isRunning():
      server.loop.stop()
    else:
      server.loop.close()

proc run*(server: HttpServer) =
  ## Block serving until `stop`/`close`. When the server owns its loop,
  ## the server is closed and the loop freed on exit.
  server.loop.run()
  if server.ownsLoop and server.loop != nil and not server.loop.closed:
    server.close()

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
