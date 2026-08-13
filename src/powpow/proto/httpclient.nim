# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## HTTP/1.1 client for powpow — async and sync.
##
## `AsyncHttpClient` owns its own event loop and is awaited with asyncdispatch:
##
##   ```nim
##   import std/asyncdispatch
##
##   let client = newAsyncHttpClient()
##   proc main() {.async.} =
##     let res = await client.get("http://localhost:9000/")
##     echo res.getStatusCode(), " ", res.getBodyString()
##     client.close()
##   waitFor main()
##   ```
##
## `HttpClient` is the blocking variant. It owns a private event loop and
## returns the response directly, raising `HttpError` on failure:
##
##   ```nim
##   let client = newHttpClient()
##   let res = client.get("http://localhost:9000/")
##   echo res.getStatusCode(), " ", res.getBodyString()
##   client.close()
##   ```
##
## Both support Unix domain sockets via the `unixSocket` argument (POSIX only)
## and HTTPS via a `SslContext` from `newClientTlsContext`.
##
## Connections are reused across sequential requests when `keepAlive` is true
## (the default). Response headers/body must be consumed before issuing the
## next request on the same client. `close` shuts down the client's idle
## connection and its private loop.

import std/[asyncdispatch, httpcore, strutils]

import ../net/tcp
import ../net/common
import ../net/tls
import ../loop
import ../types
import ./http

# ── Types ────────────────────────────────────────────────────────────────────

const DefaultMaxResponseBody* = 64 * 1024 * 1024
  ## Default per-response body cap. A server declaring a larger Content-Length
  ## (or delivering more chunked data) fails the request instead of letting the
  ## parser buffer it in RAM (unbounded-response memory DoS).

type
  HttpError* = object of CatchableError

  HttpClientBase* = ref object of RootObj
    tlsCtx*: SslContext
    keepAlive*: bool
    timeoutMs*: int
    maxBodySize*: int
    defaultHeaders*: seq[(string, string)]
    idleConn: Connection
    idleParser: HttpParser

  AsyncHttpClient* = ref object of HttpClientBase
    loop*: Loop
    activeRequests: int   ## guards against concurrent awaits on one client

  HttpClient* = ref object of HttpClientBase
    syncLoop: Loop

  HttpClientResponse* = ref object
    ## A parsed HTTP response (client side). Accessors materialize lazily from
    ## the underlying parser; with `keepAlive`, consume them before the next
    ## request reuses the connection.
    parser*: HttpParser
    reqConn*: Connection

  HttpReq = ref object
    client: HttpClientBase
    conn: Connection
    parser: HttpParser
    onResponse: proc(res: HttpClientResponse) {.closure.}
    onBodyData: HttpBodyCallback
    onError: proc(err: string) {.closure.}
    delivered: bool
    active: bool
    timer: TimerId
    noBodyExpected: bool      # request method implies no response body (HEAD)
    pendingCloseDelimited: bool  # body delimited by connection close

# ── URL parsing ──────────────────────────────────────────────────────────────

proc hasControlChars(s: string): bool {.inline.} =
  ## CR/LF (and other C0 controls / DEL) in a URL host or path would be
  ## written verbatim into the request line / Host header — request injection.
  for c in s:
    let o = ord(c)
    if o < 0x20 or o == 0x7F:
      return true

proc parseHttpUrl(url: string): tuple[scheme, host, path: string; port: int] =
  let sEnd = url.find("://")
  if sEnd <= 0:
    raise newException(HttpError, "invalid URL (expected scheme://host[:port]/path): " & url)
  let scheme = url[0 ..< sEnd].toLowerAscii()
  if scheme != "http" and scheme != "https":
    raise newException(HttpError, "unsupported URL scheme: " & scheme)
  let rest = url[sEnd + 3 .. ^1]
  let pStart = rest.find('/')
  var authority = if pStart < 0: rest else: rest[0 ..< pStart]
  let path = if pStart < 0: "/" else: rest[pStart .. ^1]
  if hasControlChars(authority) or hasControlChars(path):
    raise newException(HttpError, "control character in URL")
  var host = ""
  var portStr = ""
  if authority.startsWith('['):
    let close = authority.find(']')
    if close < 0:
      raise newException(HttpError, "invalid IPv6 authority: " & authority)
    host = authority[1 ..< close]
    if close + 1 < authority.len:
      if authority[close + 1] != ':':
        raise newException(HttpError, "invalid authority: " & authority)
      portStr = authority[close + 2 .. ^1]
  else:
    let colon = authority.rfind(':')
    if colon >= 0:
      host = authority[0 ..< colon]
      portStr = authority[colon + 1 .. ^1]
    else:
      host = authority
  if host.len == 0:
    raise newException(HttpError, "missing host in URL: " & url)
  var port = if scheme == "https": 443 else: 80
  if portStr.len > 0:
    try:
      port = parseInt(portStr)
    except ValueError:
      raise newException(HttpError, "invalid port: " & portStr)
  (scheme, host, path, port)

# ── Request building ─────────────────────────────────────────────────────────

proc validHeaderField(s: string): bool {.inline.} =
  ## Header keys/values are written verbatim into the request; a CR/LF/NUL
  ## would inject additional headers or a second request (request smuggling).
  for c in s:
    if c == '\r' or c == '\n' or c == '\0':
      return false
  true

proc buildRequestHeaders(client: HttpClientBase, meth: HttpMethod,
                         path, hostForHeader: string, bodyLen: int,
                         headers: openArray[(string, string)]): string =
  result = newStringOfCap(256 + bodyLen)
  result.add($meth); result.add(" "); result.add(path); result.add(" HTTP/1.1\r\n")
  result.add("Host: "); result.add(hostForHeader); result.add("\r\n")
  result.add("Content-Length: "); result.add($bodyLen); result.add("\r\n")
  result.add(if client.keepAlive: "Connection: keep-alive\r\n" else: "Connection: close\r\n")
  for (k, v) in client.defaultHeaders:
    if not validHeaderField(k) or not validHeaderField(v):
      raise newException(HttpError, "CR/LF in HTTP header")
    result.add(k); result.add(": "); result.add(v); result.add("\r\n")
  for (k, v) in headers:
    if not validHeaderField(k) or not validHeaderField(v):
      raise newException(HttpError, "CR/LF in HTTP header")
    result.add(k); result.add(": "); result.add(v); result.add("\r\n")
  result.add("\r\n")

# ── Request lifecycle ────────────────────────────────────────────────────────

proc failReq(st: HttpReq, client: HttpClientBase, msg: string) =
  if not st.active: return
  st.active = false
  if st.timer != TimerId(0):
    if st.conn != nil:
      st.conn.loop.cancelTimer(st.timer)
    st.timer = TimerId(0)
  if client.idleConn == st.conn:
    client.idleConn = nil
    client.idleParser = nil
  if st.conn != nil:
    st.conn.close()
  if not st.delivered and st.onError != nil:
    st.onError(msg)
  st.delivered = true

proc deliverReq(st: HttpReq, client: HttpClientBase) =
  if not st.active: return
  st.active = false
  if st.timer != TimerId(0):
    st.conn.loop.cancelTimer(st.timer)
    st.timer = TimerId(0)
  st.delivered = true
  let res = HttpClientResponse(parser: st.parser, reqConn: st.conn)
  if client.keepAlive and st.conn.state == Connected and
     st.parser.getHttpMinor() == 1 and not st.parser.getConnectionClose():
    client.idleConn = st.conn
    client.idleParser = st.parser
  else:
    st.conn.close()
  if st.onResponse != nil:
    st.onResponse(res)

proc noBodyStatus(code: HttpCode): bool {.inline.} =
  ## 1xx, 204 and 304 responses carry no body regardless of Content-Length.
  let c = code.int
  (c >= 100 and c < 200) or c == 204 or c == 304

proc closeDelimitedResponse(st: HttpReq): bool =
  ## True when the completed headers describe a close-delimited body: no
  ## Content-Length, no Transfer-Encoding, and a body is expected.
  let p = st.parser
  p.getContentLength() < 0 and not p.isChunked() and
    not st.noBodyExpected and not noBodyStatus(p.getStatusCode())

proc requestImpl(client: HttpClientBase, loop: Loop, meth: HttpMethod,
                 url: string, body: openArray[byte],
                 headers: openArray[(string, string)],
                 unixSocket: string, timeoutOverride: int,
                 onResponse: proc(res: HttpClientResponse) {.closure.},
                 onBodyData: HttpBodyCallback,
                 onError: proc(err: string) {.closure.}): HttpReq =
  let parsed = parseHttpUrl(url)
  let timeout = if timeoutOverride < 0: client.timeoutMs else: timeoutOverride
  let hostForHeader =
    if (parsed.port != 80 and parsed.port != 443):
      parsed.host & ":" & $parsed.port
    else:
      parsed.host
  let tlsNeeded = parsed.scheme == "https"
  let reqHeaders = buildRequestHeaders(client, meth, parsed.path, hostForHeader,
                                       body.len, headers)
  let bodyBytes = @body

  let st = HttpReq(
    client: client,
    onResponse: onResponse,
    onBodyData: onBodyData,
    onError: onError,
    active: true,
    timer: TimerId(0),
  )

  if timeout > 0:
    st.timer = loop.addTimer(timeout) do (id: int):
      if st.active:
        failReq(st, client, "request timed out")

  proc onFd(st: HttpReq, client: HttpClientBase, fd: int, ev: set[EventType]) =
    let conn = st.conn
    if conn == nil or conn.state != Connected:
      return
    if not st.active:
      # Stale event on an idle/closed connection — drop the idle slot.
      if client.idleConn == conn:
        client.idleConn = nil
        client.idleParser = nil
        conn.close()
      return
    if Error in ev and Read notin ev:
      failReq(st, client, "connection error")
      return
    if conn.tlsState == TlsHandshaking:
      if not conn.driveHandshake():
        return
    if Write in ev:
      if conn.flushWriteBuffer():
        if conn.state != Connected:
          failReq(st, client, "connection closed while writing")
          return
        if conn.tlsState != TlsHandshaking:
          conn.loop.modify(fd, {Read})
    if Read in ev or Hup in ev:
      var buf: array[65536, byte]
      while true:
        var n: int
        when defined(windows):
          n = conn.loop.platform.getReadData(
            conn.fd.int, cast[ptr UncheckedArray[byte]](addr buf[0]), buf.len)
        else:
          n = sockRecv(conn.fd, addr buf[0], buf.len)
        if n > 0:
          discard st.parser.feed(buf.toOpenArray(0, n - 1))
          if st.parser.isError():
            failReq(st, client, "invalid HTTP response")
            return
          if st.parser.headersDone and st.parser.headerEnd > MaxHeaderSize:
            # The parser's header cap only fires while the section is still
            # incomplete; a hostile header block that arrives in one packet
            # must still be rejected.
            failReq(st, client, "response headers too large")
            return
          if st.parser.isComplete():
            if st.closeDelimitedResponse():
              # Headers done, no framing — wait for EOF, then promote the
              # buffered bytes to the body.
              st.pendingCloseDelimited = true
            else:
              deliverReq(st, client)
              return
          elif st.parser.headersDone and
               (st.noBodyExpected or noBodyStatus(st.parser.getStatusCode())):
            # Body-less response (HEAD request, 1xx/204/304): the parser
            # would wait on a Content-Length that never arrives.
            deliverReq(st, client)
            return
        elif n == 0:
          if st.pendingCloseDelimited or
             (st.parser.phase == PhaseComplete and st.closeDelimitedResponse()):
            st.parser.finalizeCloseDelimited()
            deliverReq(st, client)
          elif st.parser.phase == PhaseComplete:
            deliverReq(st, client)
          else:
            failReq(st, client, "connection closed before response completed")
          return
        else:
          when defined(windows):
            # getReadData < 0: a WSARecv is in flight with no data buffered
            # yet — wait for the next completion instead of treating it as an
            # error (mirrors POSIX EAGAIN).
            break
          else:
            if sockWouldBlock():
              break
            if sockInterrupted():
              continue
            failReq(st, client, "recv error")
            return
      if (Hup in ev or Error in ev) and conn.state == Connected and st.active:
        if st.parser.phase == PhaseComplete:
          if st.pendingCloseDelimited or st.closeDelimitedResponse():
            st.parser.finalizeCloseDelimited()
          deliverReq(st, client)
        else:
          failReq(st, client, "connection closed before response completed")

  proc begin(conn: Connection, reuseParser: HttpParser = nil) =
    st.conn = conn
    if not st.active:
      conn.close()
      return
    st.noBodyExpected = meth == HttpHead
    try:
      if tlsNeeded:
        if client.tlsCtx == nil:
          failReq(st, client, "https requested but no tlsCtx configured")
          return
        conn.wrapTls(client.tlsCtx, parsed.host)
    except SslError:
      failReq(st, client, getCurrentExceptionMsg())
      return
    if reuseParser != nil:
      st.parser = reuseParser
      st.parser.resetForNext()
    else:
      st.parser = newHttpParser()
    st.parser.responseMode = true
    st.parser.maxBodySize = client.maxBodySize.int64
    if st.onBodyData != nil:
      st.parser.onBodyData = st.onBodyData
    discard conn.send(reqHeaders)
    if bodyBytes.len > 0:
      discard conn.send(bodyBytes)
    # Re-register in place: register() already replaces the existing watcher.
    # Unregistering first would trash the fd state while its WSARecv is still
    # in flight on Windows/IOCP, so the response bytes would land in the trash
    # and be lost (hanging the request or surfacing as a connection error).
    conn.loop.register(conn.fd.int, {Read, Write}, edgeTriggered = true,
      callback = proc(fd: int, ev: set[EventType]) =
        onFd(st, client, fd, ev))

  # Reuse the idle keep-alive connection when available.
  if client.idleConn != nil and client.idleParser != nil and
     client.idleConn.loop == loop and client.idleConn.state == Connected:
    let conn = client.idleConn
    let parser = client.idleParser
    client.idleConn = nil
    client.idleParser = nil
    begin(conn, parser)
    return st

  when not defined(windows):
    if unixSocket.len > 0:
      try:
        loop.connectUnix(unixSocket,
          onConnect = proc(conn: Connection) =
            begin(conn)
          ,
          onData = proc(conn: Connection, data: openArray[byte]) = discard,
          onClose = proc(conn: Connection) =
            if st.active:
              failReq(st, client, "connection closed during request")
        )
      except NetError as e:
        failReq(st, client, e.msg)
      return st

  loop.connect(parsed.host, parsed.port,
    onConnect = proc(conn: Connection) =
      begin(conn)
    ,
    onData = proc(conn: Connection, data: openArray[byte]) = discard,
    onClose = proc(conn: Connection) =
      if st.active:
        failReq(st, client, "connection closed during request")
    ,
    onError = proc(err: string) =
      if st.active:
        failReq(st, client, err)
  )
  st

# ── Response accessors ───────────────────────────────────────────────────────

proc getStatusCode*(res: HttpClientResponse): HttpCode {.inline.} =
  res.parser.getStatusCode()

proc getStatusText*(res: HttpClientResponse): lent string {.inline.} =
  res.parser.getStatusText()

proc getHeaders*(res: HttpClientResponse): HttpHeaders {.inline.} =
  res.parser.getHeaders()

proc getBody*(res: HttpClientResponse): seq[byte] {.inline.} =
  res.parser.getBody()

proc getBodyString*(res: HttpClientResponse): string =
  let b = res.parser.getBody()
  if b.len == 0: return ""
  result = newString(b.len)
  copyMem(addr result[0], unsafeAddr b[0], b.len)

proc getContentLength*(res: HttpClientResponse): int {.inline.} =
  res.parser.getContentLength()

proc getConnectionClose*(res: HttpClientResponse): bool {.inline.} =
  res.parser.getConnectionClose()

proc isOk*(res: HttpClientResponse): bool {.inline.} =
  res.getStatusCode() in {Http200, Http201, Http202, Http203, Http204, Http205, Http206}

# ── Constructors / close ─────────────────────────────────────────────────────

proc newAsyncHttpClient*(tlsCtx: SslContext = nil,
                         keepAlive: bool = true,
                         timeoutMs: int = 0,
                         maxBodySize: int = DefaultMaxResponseBody): AsyncHttpClient =
  ## Create an async HTTP client with its own event loop. Await the request
  ## methods from an `async` proc with asyncdispatch.
  AsyncHttpClient(
    loop: newLoop(),
    tlsCtx: tlsCtx,
    keepAlive: keepAlive,
    timeoutMs: timeoutMs,
    maxBodySize: maxBodySize,
    defaultHeaders: @[],
  )

proc newHttpClient*(tlsCtx: SslContext = nil, keepAlive: bool = true,
                    timeoutMs: int = 0,
                    maxBodySize: int = DefaultMaxResponseBody): HttpClient =
  HttpClient(
    syncLoop: newLoop(),
    tlsCtx: tlsCtx,
    keepAlive: keepAlive,
    timeoutMs: timeoutMs,
    maxBodySize: maxBodySize,
    defaultHeaders: @[],
  )

proc getLoop*(client: HttpClient): Loop {.inline.} =
  ## The private loop the sync client blocks on. Exposed so other subsystems
  ## (e.g. a test server) can be hosted on the same loop and driven by the
  ## client's `poll` while a request is in flight.
  client.syncLoop

proc close*(client: AsyncHttpClient) =
  ## Close the idle keep-alive connection and the client's event loop.
  if client.idleConn != nil:
    client.idleConn.close()
    client.idleConn = nil
    client.idleParser = nil
  client.loop.close()

proc close*(client: HttpClient) =
  ## Close the idle keep-alive connection and the client's event loop.
  if client.idleConn != nil:
    client.idleConn.close()
    client.idleConn = nil
    client.idleParser = nil
  client.syncLoop.close()

# ── Async API (await-able) ───────────────────────────────────────────────────

proc request*(
    client: AsyncHttpClient,
    meth: HttpMethod,
    url: string,
    body: openArray[byte] = [],
    headers: openArray[(string, string)] = [],
    unixSocket: string = "",
    timeoutMs: int = -1,
): Future[HttpClientResponse] =
  ## Send an async HTTP request and await the response. The client owns its
  ## event loop, which is driven cooperatively with asyncdispatch while the
  ## request is in flight.
  let fut = newFuture[HttpClientResponse]()
  if client.activeRequests > 0:
    fut.fail(newException(HttpError,
      "concurrent requests on one AsyncHttpClient are not supported"))
    return fut
  inc client.activeRequests
  var done = false
  var resp: HttpClientResponse
  var errMsg = ""
  proc finish() =
    if done: return
    done = true
    dec client.activeRequests
    if errMsg.len > 0:
      fut.fail(newException(HttpError, errMsg))
    elif resp != nil:
      fut.complete(resp)
    else:
      fut.fail(newException(HttpError, "request did not complete"))
  try:
    discard requestImpl(client, client.loop, meth, url, body, headers,
                        unixSocket, timeoutMs,
      onResponse = proc(res: HttpClientResponse) =
        resp = res
        finish()
      ,
      onBodyData = nil,
      onError = proc(err: string) =
        errMsg = err
        finish()
    )
  except HttpError as e:
    errMsg = e.msg
    finish()
  proc pump() {.async.} =
    ## Drive the client's loop in lockstep with the asyncdispatch dispatcher
    ## until the request completes.
    while not done:
      client.loop.poll(0)
      if not done:
        await sleepAsync(1)
  discard pump()
  fut

proc request*(
    client: AsyncHttpClient,
    meth: HttpMethod,
    url: string,
    body: string,
    headers: openArray[(string, string)] = [],
    unixSocket: string = "",
    timeoutMs: int = -1,
): Future[HttpClientResponse] =
  client.request(meth, url, body.toOpenArrayByte(0, body.high), headers,
                 unixSocket, timeoutMs)

template asyncVerb(verb: untyped, meth: HttpMethod) =
  proc verb*(
      client: AsyncHttpClient,
      url: string,
      headers: openArray[(string, string)] = [],
      unixSocket: string = "",
      timeoutMs: int = -1,
  ): Future[HttpClientResponse] =
    client.request(meth, url, [], headers, unixSocket, timeoutMs)

  proc verb*(
      client: AsyncHttpClient,
      url: string,
      body: string,
      headers: openArray[(string, string)] = [],
      unixSocket: string = "",
      timeoutMs: int = -1,
  ): Future[HttpClientResponse] =
    client.request(meth, url, body.toOpenArrayByte(0, body.high), headers,
                   unixSocket, timeoutMs)

asyncVerb(get, HttpGet)
asyncVerb(post, HttpPost)
asyncVerb(put, HttpPut)
asyncVerb(delete, HttpDelete)
asyncVerb(head, HttpHead)
asyncVerb(patch, HttpPatch)
asyncVerb(options, HttpOptions)

# ── Sync API ─────────────────────────────────────────────────────────────────

proc request*(
    client: HttpClient,
    meth: HttpMethod,
    url: string,
    body: openArray[byte] = [],
    headers: openArray[(string, string)] = [],
    unixSocket: string = "",
    timeoutMs: int = -1,
): HttpClientResponse =
  ## Blocking HTTP request. Returns the response or raises `HttpError`.
  ## `timeoutMs`: -1 = client default, 0 = no timeout, >0 = override.
  var done = false
  var resp: HttpClientResponse
  var errMsg = ""
  let st = requestImpl(client, client.syncLoop, meth, url, body, headers,
                       unixSocket, timeoutMs,
    onResponse = proc(res: HttpClientResponse) =
      resp = res
      done = true
    ,
    onBodyData = nil,
    onError = proc(err: string) =
      errMsg = err
      done = true
  )
  while not done:
    client.syncLoop.poll()
  if errMsg.len > 0:
    raise newException(HttpError, errMsg)
  if resp == nil:
    raise newException(HttpError, "request did not complete")
  resp

proc request*(
    client: HttpClient,
    meth: HttpMethod,
    url: string,
    body: string,
    headers: openArray[(string, string)] = [],
    unixSocket: string = "",
    timeoutMs: int = -1,
): HttpClientResponse =
  client.request(meth, url, body.toOpenArrayByte(0, body.high), headers,
                 unixSocket, timeoutMs)

template syncVerb(verb: untyped, meth: HttpMethod) =
  proc verb*(
      client: HttpClient,
      url: string,
      headers: openArray[(string, string)] = [],
      unixSocket: string = "",
      timeoutMs: int = -1,
  ): HttpClientResponse =
    client.request(meth, url, [], headers, unixSocket, timeoutMs)

  proc verb*(
      client: HttpClient,
      url: string,
      body: string,
      headers: openArray[(string, string)] = [],
      unixSocket: string = "",
      timeoutMs: int = -1,
  ): HttpClientResponse =
    client.request(meth, url, body.toOpenArrayByte(0, body.high), headers,
                   unixSocket, timeoutMs)

syncVerb(get, HttpGet)
syncVerb(post, HttpPost)
syncVerb(put, HttpPut)
syncVerb(delete, HttpDelete)
syncVerb(head, HttpHead)
syncVerb(patch, HttpPatch)
syncVerb(options, HttpOptions)
