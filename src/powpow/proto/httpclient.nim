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
## Keep-alive connections are pooled per origin when `keepAlive` is true (the
## default): up to `maxIdlePerHost` per host and `maxIdleTotal` overall, each
## trusted for reuse for `idleTimeoutMs`. A pooled connection that the server
## closed between requests is detected and retried transparently on a fresh
## connection (as long as no response bytes arrived). Interim `100 Continue`
## responses are consumed automatically, so callers may send
## `Expect: 100-continue` via request headers. Response headers/body must be
## consumed before issuing the next request. `close` drains the pool and shuts
## down the client's private loop.

import std/httpcore except HttpMethod
import std/[asyncdispatch, base64, strutils, tables, times]

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

const DefaultMaxIdlePerHost* = 4
  ## Default cap on idle keep-alive connections held per origin.
const DefaultMaxIdleTotal* = 16
  ## Default overall cap on idle keep-alive connections.
const DefaultIdleTimeoutMs* = 60_000
  ## How long an idle keep-alive connection is trusted for reuse (0 = no
  ## timeout). Eviction is lazy: stale entries are dropped when a request
  ## would use them, not on a background timer.

type
  HttpError* = object of CatchableError

  PoolKey* = tuple[host: string, port: int, tls: bool, uds: string,
                     proxy: string]
    ## Origin identity of a pooled connection. Two URLs share a connection only
    ## when every field matches — reusing across origins would send requests
    ## to the wrong host. `proxy` is "" for direct connections, the proxy
    ## authority for plain-http proxying, and proxy+target for CONNECT
    ## tunnels (a tunnel is bound to its target).

  PooledConn* = object
    conn*: Connection
    parser*: HttpParser
    idleSinceMs*: int64   ## When the connection became idle (monoMs clock)
    order*: int64         ## Monotonic insertion stamp — deterministic eviction
                          ## tiebreak when pushes land in the same millisecond

  HttpConnPool* = ref object
    ## Idle keep-alive connection pool, keyed by origin. LIFO per key (the most
    ## recently used connection is reused first — its TCP path is still warm).
    conns*: Table[PoolKey, seq[PooledConn]]
    totalIdle*: int
    orderCounter: int64
    maxPerHost*: int
    maxTotal*: int
    idleTimeoutMs*: int

  Cookie* = object
    ## One stored cookie (RFC 6265 subset).
    name*, value*: string
    domain*: string    ## lowercased, no leading dot
    path*: string      ## default "/"
    expiresMs*: int64  ## 0 = session cookie
    secure*: bool
    hostOnly*: bool    ## true when no Domain attribute was sent

  CookieJar* = ref object
    ## Simple cookie store. Attach with `client.cookieJar = newCookieJar()`
    ## to persist cookies across requests; stored cookies are sent only to
    ## domain/path-matching origins (Secure only over https).
    cookies*: seq[Cookie]

  HttpClientBase* = ref object of RootObj
    tlsCtx*: SslContext
    keepAlive*: bool
    timeoutMs*: int
    maxBodySize*: int
    defaultHeaders*: seq[(string, string)]
    pool*: HttpConnPool     ## Idle keep-alive connections by origin
    maxRedirects*: int      ## Follow 301/302/303/307/308 (0 = return as-is)
    cookieJar*: CookieJar   ## Cookie store (nil = disabled)
    proxyUrl*: string        ## http://[user:pass@]host[:port] proxy ("" = direct)
    connectTimeoutMs*: int  ## connect+handshake deadline (0 = total governs)
    readTimeoutMs*: int     ## response-inactivity deadline (0 = off)

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
    tlsHost: string           ## SNI/verify target (differs from key.host via proxy)
    needsProxyTunnel: bool    ## https-over-proxy: CONNECT first, then TLS
    proxyPending: bool        ## CONNECT handshake in flight (recomputed per conn)
    proxyHead: string         ## prebuilt CONNECT request line + headers
    proxyBuf: string          ## CONNECT response accumulator (16 KiB cap)
    loop: Loop              ## owning loop (timer ops when conn is nil)
    startMs: int64          ## request start (monoMs)
    deadlineTotalMs: int64  ## absolute total deadline (0 = none)
    connectTimeoutMs: int   ## per-request copy of the client knob
    readTimeoutMs: int      ## per-request copy of the client knob
    connectDone: bool       ## app bytes flowing (TCP + TLS + tunnel up)
    key: PoolKey              # origin this request targets (pool identity)
    cameFromPool: bool        # conn was reused from the pool — retry once on stale
    retried: bool             # already did the fresh-connection retry
    tlsNeeded: bool           # request goes over TLS (wrap on connect)
    reqHeaders: string        # serialized request head (built once)
    bodyBytes: seq[byte]      # request body copy (sent after reqHeaders)

# ── Connection pool ──────────────────────────────────────────────────────────

func newHttpConnPool*(maxPerHost: int = DefaultMaxIdlePerHost,
                      maxTotal: int = DefaultMaxIdleTotal,
                      idleTimeoutMs: int = DefaultIdleTimeoutMs): HttpConnPool =
  HttpConnPool(maxPerHost: maxPerHost, maxTotal: maxTotal,
               idleTimeoutMs: idleTimeoutMs)

proc closePooled(pc: PooledConn) {.inline.} =
  pc.conn.close()

proc evictOldest(pool: HttpConnPool) =
  ## Close and drop the globally oldest idle connection (smallest
  ## `idleSinceMs`). No-op on an empty pool.
  var oldestKey: PoolKey
  var oldestIdx = -1
  var oldestOrder = int64.high
  for key, seqs in pool.conns:
    for i in 0 ..< seqs.len:
      if seqs[i].order < oldestOrder:
        oldestOrder = seqs[i].order
        oldestKey = key
        oldestIdx = i
  if oldestIdx >= 0:
    closePooled(pool.conns[oldestKey][oldestIdx])
    pool.conns[oldestKey].delete(oldestIdx)
    if pool.conns[oldestKey].len == 0:
      pool.conns.del(oldestKey)
    dec pool.totalIdle

proc push*(pool: HttpConnPool, key: PoolKey, conn: Connection,
           parser: HttpParser) =
  ## Return a keep-alive connection to the pool, enforcing per-host and total
  ## caps (oldest connections are closed first).
  if conn.state != Connected or parser.isNil:
    conn.close()
    return
  pool.conns.withValue(key, list):
    # Per-host cap: drop the oldest of this origin.
    while list[].len >= max(pool.maxPerHost, 1):
      closePooled(list[][0])
      list[].delete(0)
      dec pool.totalIdle
  inc pool.orderCounter
  let pc = PooledConn(conn: conn, parser: parser,
                      idleSinceMs: monoMs(), order: pool.orderCounter)
  pool.conns.mgetOrPut(key, default(seq[PooledConn])).add(pc)
  inc pool.totalIdle
  while pool.totalIdle > max(pool.maxTotal, 1):
    pool.evictOldest()

proc pop*(pool: HttpConnPool, loop: Loop, key: PoolKey): PooledConn =
  ## Take the most recently idled connection for `key`, skipping entries that
  ## have expired (lazy idle timeout) or died. Returns default(PooledConn)
  ## (conn == nil) when none is usable.
  while true:
    var list: ptr seq[PooledConn] = addr pool.conns.mgetOrPut(key, default(seq[PooledConn]))
    if list[].len == 0:
      pool.conns.del(key)
      return
    let idx = list[].len - 1  # LIFO
    var pc = list[][idx]
    list[].delete(idx)
    if list[].len == 0:
      pool.conns.del(key)
    dec pool.totalIdle
    # Lazy expiry check.
    if pool.idleTimeoutMs > 0 and monoMs() - pc.idleSinceMs > pool.idleTimeoutMs:
      closePooled(pc)
      continue
    if pc.conn.state != Connected or pc.conn.loop != loop:
      closePooled(pc)
      continue
    return pc

proc removeFromPool*(pool: HttpConnPool, conn: Connection): bool =
  ## Drop `conn` from the pool (closing it). True when it was pooled.
  for key, list in pool.conns.mpairs:
    for i in 0 ..< list.len:
      if list[i].conn == conn:
        closePooled(list[i])
        list.delete(i)
        dec pool.totalIdle
        if list.len == 0:
          pool.conns.del(key)
        return true
  false

proc closeAll*(pool: HttpConnPool) =
  for key, list in pool.conns.mpairs:
    for pc in list:
      closePooled(pc)
  pool.conns.clear()
  pool.totalIdle = 0

func idleConnections*(pool: HttpConnPool): int {.inline.} =
  pool.totalIdle

func idleConnectionsFor*(pool: HttpConnPool, key: PoolKey): int {.inline.} =
  if pool.conns.hasKey(key): pool.conns[key].len else: 0

proc parseHttpUrl(url: string): tuple[scheme, host, path: string; port: int]
  ## Forward declaration (defined below, URL parsing): the redirect
  ## and cookie engines resolve URLs.

# ── Cookies ─────────────────────────────────────

proc getStatusCode*(res: HttpClientResponse): HttpCode {.inline.} =
  res.parser.getStatusCode()

proc getHeaderValue*(res: HttpClientResponse, name: string): string {.inline.} =
  ## Single response header, case-insensitive ("" when absent). Last-wins on
  ## repeats — use `getHeaderValues` for `Set-Cookie` and friends.
  $res.parser.getHeaderValue(name)

proc getHeaderValues*(res: HttpClientResponse, name: string): seq[string] {.inline.} =
  ## All values of a repeated response header (e.g. `Set-Cookie`), in order.
  res.parser.getHeaderValues(name)

proc newCookieJar*(): CookieJar =
  ## Create an empty cookie store. Attach it to a client:
  ## `client.cookieJar = newCookieJar()`.
  CookieJar(cookies: @[])

proc parseHttpDateMs(s: string): int64 =
  ## Parse an HTTP date (a cookie `Expires` attribute) to epoch
  ## milliseconds. Returns 0 when unparseable (session cookie).
  for layout in ["ddd, dd MMM yyyy HH:mm:ss 'GMT'",
                 "dddd, dd-MMM-yy HH:mm:ss 'GMT'",
                 "ddd MMM dd HH:mm:ss yyyy"]:
    try:
      return times.parse(s, layout, utc()).toTime.toUnix * 1000
    except TimeParseError:
      discard
  0

proc domainMatches(host, domain: string, hostOnly: bool): bool {.inline.} =
  if host == domain:
    return true
  if hostOnly:
    return false
  host.endsWith("." & domain)

proc pathMatches(reqPath, cookiePath: string): bool =
  if reqPath == cookiePath:
    return true
  if reqPath.startsWith(cookiePath):
    if cookiePath.endsWith("/"):
      return true
    if reqPath.len > cookiePath.len and reqPath[cookiePath.len] == '/':
      return true
  false

proc defaultCookiePath(reqPath: string): string =
  ## RFC 6265 section 5.1.4 default-path: the request path up to its last
  ## `/` ("/" when there is none or it is the only character).
  var p = reqPath
  let q = p.find('?')
  if q >= 0:
    p = p[0 ..< q]
  let slash = p.rfind('/')
  if slash <= 0:
    return "/"
  p[0 ..< slash]

proc storeResponseCookies*(jar: CookieJar, url: string,
                           res: HttpClientResponse) =
  ## Store every `Set-Cookie` header of `res` (RFC 6265 section 5.3).
  ## Malformed cookies are skipped; `Max-Age <= 0` deletes. Raises HttpError
  ## on an invalid `url` (never for URLs our own requests built).
  let (_, host, path, _) = parseHttpUrl(url)
  let reqHost = host.toLowerAscii()
  let nowMs = monoMs()
  for sc in res.getHeaderValues("set-cookie"):
    let semi = sc.find(';')
    let nv = (if semi < 0: sc else: sc[0 ..< semi]).strip()
    let eq = nv.find('=')
    if eq <= 0:
      continue
    let name = nv[0 ..< eq].strip()
    if name.len == 0:
      continue
    var val = if eq + 1 > nv.high: "" else: nv[eq + 1 .. ^1].strip()
    if val.len >= 2 and val[0] == '"' and val[^1] == '"':
      val = val[1 .. ^2]
    var c = Cookie(name: name, value: val, domain: reqHost,
                   path: defaultCookiePath(path), hostOnly: true)
    var valid = true
    var delete = false
    var hasMaxAge = false
    let attrs = if semi < 0: "" else: sc[semi + 1 .. ^1]
    for rawAttr in attrs.split(';'):
      let attr = rawAttr.strip()
      if attr.len == 0:
        continue
      let ae = attr.find('=')
      var aname, aval: string
      if ae < 0:
        aname = attr.toLowerAscii()
        aval = ""
      else:
        aname = attr[0 ..< ae].strip().toLowerAscii()
        aval = if ae + 1 > attr.high: "" else: attr[ae + 1 .. ^1].strip()
      case aname
      of "domain":
        var d = aval.toLowerAscii()
        if d.startsWith("."):
          d = d[1 .. ^1]
        if d.len == 0 or not domainMatches(reqHost, d, false):
          valid = false
          break
        c.domain = d
        c.hostOnly = false
      of "path":
        if aval.startsWith("/"):
          c.path = aval
      of "max-age":
        try:
          let n = parseInt(aval)
          hasMaxAge = true
          if n <= 0:
            delete = true
          else:
            c.expiresMs = nowMs + n.int64 * 1000
        except ValueError:
          discard
      of "expires":
        if not hasMaxAge:
          let ms = parseHttpDateMs(aval)
          if ms > 0:
            c.expiresMs = ms
      of "secure":
        c.secure = true
      else:
        discard
    if not valid:
      continue
    var idx = -1
    for i in 0 ..< jar.cookies.len:
      let e = jar.cookies[i]
      if e.name == c.name and e.domain == c.domain and e.path == c.path:
        idx = i
        break
    if idx >= 0:
      jar.cookies.delete(idx)
    if not delete:
      jar.cookies.add(c)

proc cookieHeaderForUrl*(jar: CookieJar, url: string): string =
  ## The `Cookie` header value for `url` ("n=v; n2=v2"), or "" when nothing
  ## matches. Expired cookies are purged lazily; Secure cookies only match
  ## https URLs. Raises HttpError on an invalid `url`.
  let (scheme, host, path, _) = parseHttpUrl(url)
  let reqHost = host.toLowerAscii()
  let secureCtx = scheme == "https"
  let nowMs = monoMs()
  var cleanPath = path
  let q = cleanPath.find('?')
  if q >= 0:
    cleanPath = cleanPath[0 ..< q]
  if cleanPath.len == 0:
    cleanPath = "/"
  var kept: seq[Cookie] = @[]
  var first = true
  for c in jar.cookies:
    if c.expiresMs > 0 and c.expiresMs <= nowMs:
      continue
    kept.add(c)
    if c.secure and not secureCtx:
      continue
    if not domainMatches(reqHost, c.domain, c.hostOnly):
      continue
    if not pathMatches(cleanPath, c.path):
      continue
    if not first:
      result.add("; ")
    result.add(c.name & "=" & c.value)
    first = false
  jar.cookies = move(kept)

# ── Redirects ────────────────────────────────────

const MaxRedirectHops* = 32
  ## Hard cap on redirect hops per request — loop protection even when
  ## `maxRedirects` is set higher.

const redirectCodes = {Http301, Http302, Http303, Http307, Http308}

proc authorityHost(host: string): string {.inline.} =
  ## Wrap bare IPv6 literals for authority/Host use.
  if ':' in host: '[' & host & ']' else: host

proc resolveRedirectUrl*(baseUrl, loc: string): string =
  ## Resolve a `Location` value against the requesting URL. Returns "" for
  ## an empty or fragment-only location (don't follow). Absolute URIs pass
  ## through (validated when followed); rooted, scheme-relative, relative
  ## and query-only locations merge against the base. Raises HttpError on an
  ## invalid base (never for URLs our own requests built).
  var l = loc
  let frag = l.find('#')
  if frag >= 0:
    l = l[0 ..< frag]
  if l.len == 0:
    return ""
  if "://" in l:
    return l
  let (scheme, host, path, port) = parseHttpUrl(baseUrl)
  let defaultPort = (scheme == "http" and port == 80) or
                    (scheme == "https" and port == 443)
  let auth = if defaultPort: authorityHost(host)
             else: authorityHost(host) & ":" & $port
  if l.startsWith("//"):
    return scheme & ":" & l
  var basePath = path
  let q = basePath.find('?')
  if q >= 0:
    basePath = basePath[0 ..< q]
  if basePath.len == 0:
    basePath = "/"
  var merged: string
  if l.startsWith("/"):
    merged = l
  elif l.startsWith("?"):
    merged = basePath & l
  else:
    let slash = basePath.rfind('/')
    let dir = if slash < 0: "/" else: basePath[0 .. slash]
    merged = dir & l
  scheme & "://" & auth & merged

proc rewriteForRedirect(meth: HttpMethod, code: HttpCode,
    body: openArray[byte], headers: openArray[(string, string)],
    fromUrl, toUrl: string): tuple[meth: HttpMethod, body: seq[byte],
    headers: seq[(string, string)]] =
  ## One redirect hop: method rewrite (303 always, 301/302 for POST),
  ## body/entity-header drop on rewrite, and sensitive-header strip on
  ## cross-origin hops (scheme/host/port). Raises HttpError on invalid URLs.
  let (fs, fh, _, fp) = parseHttpUrl(fromUrl)
  let (ts, th, _, tp) = parseHttpUrl(toUrl)
  let crossOrigin = fs != ts or fh.toLowerAscii() != th.toLowerAscii() or
                    fp != tp
  var nmeth = meth
  if code == Http303 and meth != HttpHead:
    nmeth = HttpGet
  elif code in {Http301, Http302} and meth == HttpPost:
    nmeth = HttpGet
  let dropBody = nmeth != meth
  var nh: seq[(string, string)] = @[]
  for (k, v) in headers:
    let lk = k.toLowerAscii()
    if dropBody and (lk == "content-length" or lk == "content-type" or
                     lk == "transfer-encoding" or lk == "content-encoding"):
      continue
    if crossOrigin and (lk == "authorization" or lk == "cookie" or
                        lk == "proxy-authorization"):
      continue
    nh.add((k, v))
  (nmeth, if dropBody: @[] else: @body, nh)

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

proc parseProxyUrl(purl: string): tuple[host: string, port: int, auth: string] =
  ## Split an `http://[user:pass@]host[:port]` proxy URL. Only plain-http
  ## proxies are supported (an https:// proxy would need a TLS-to-proxy
  ## layer). `auth` is "" or a ready `Basic ...` value. Raises HttpError.
  let sEnd = purl.find("://")
  if sEnd <= 0:
    raise newException(HttpError, "invalid proxy URL (expected http://host[:port]): " & purl)
  if purl[0 ..< sEnd].toLowerAscii() != "http":
    raise newException(HttpError, "only http:// proxies are supported: " & purl)
  var authority = purl[sEnd + 3 .. ^1]
  let slash = authority.find('/')
  if slash >= 0:
    authority = authority[0 ..< slash]
  var auth = ""
  let at = authority.rfind('@')
  if at >= 0:
    if at == 0 or at == authority.high:
      raise newException(HttpError, "invalid proxy userinfo: " & purl)
    auth = "Basic " & base64.encode(authority[0 ..< at])
    authority = authority[at + 1 .. ^1]
  if authority.len == 0 or hasControlChars(authority):
    raise newException(HttpError, "invalid proxy authority: " & purl)
  # Reuse the origin parser for host/port validation (IPv6, default port).
  let (_, host, _, port) = parseHttpUrl("http://" & authority & "/")
  if host.len == 0:
    raise newException(HttpError, "invalid proxy authority: " & purl)
  (host, port, auth)

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
    if st.loop != nil:
      st.loop.cancelTimer(st.timer)
    st.timer = TimerId(0)
  if st.conn != nil:
    discard client.pool.removeFromPool(st.conn)
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
    client.pool.push(st.key, st.conn, st.parser)
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

proc responseStarted(st: HttpReq): bool {.inline.} =
  ## True once any response bytes have advanced the parser past the status
  ## line. Used to decide whether a failed pooled-connection reuse may be
  ## retried transparently (the server sent nothing back yet).
  st.parser != nil and st.parser.phase != PhaseRequestLine

proc retryFresh(st: HttpReq, client: HttpClientBase): bool =
  ## A pooled connection died before the server sent anything. Prepare one
  ## transparent retry on a brand-new connection (classic stale keep-alive
  ## recovery). Returns true when the caller must now open a fresh connection.
  if not st.active or not st.cameFromPool or st.retried or
     st.responseStarted() or st.conn == nil:
    return false
  st.retried = true
  st.cameFromPool = false
  if st.timer != TimerId(0):
    st.conn.loop.cancelTimer(st.timer)
    st.timer = TimerId(0)
  discard client.pool.removeFromPool(st.conn)
  st.conn.close()
  st.conn = nil
  true

proc onFdImpl(st: HttpReq, client: HttpClientBase, fd: int,
               ev: set[EventType])
  ## Forward declaration: `beginConn` registers this as the watcher callback.

proc connectFresh(st: HttpReq, client: HttpClientBase, loop: Loop)
  ## Forward declaration: `beginConn` retries on a fresh connection when the
  ## (possibly pooled) connection dies while writing the request.

proc rearm(st: HttpReq, client: HttpClientBase)
  ## Forward declaration: (re)arms the single request timer to the nearest
  ## applicable deadline (defined below, next to requestImpl).

proc proxyHandshakeBytes(st: HttpReq, client: HttpClientBase): bool
  ## Forward declaration: consumes the proxy's CONNECT response (defined
  ## below, next to onFdImpl).

proc initClientParser(st: HttpReq, client: HttpClientBase,
    reuse: HttpParser = nil) =
  ## (Re)arm the response parser: fresh, or a pooled one reset for the next
  ## response. Shared by beginConn and the CONNECT-tunnel path in onFdImpl.
  if reuse != nil:
    st.parser = reuse
    st.parser.resetForNext()
  else:
    st.parser = newHttpParser()
  st.parser.responseMode = true
  st.parser.maxBodySize = client.maxBodySize.int64
  if st.onBodyData != nil:
    st.parser.onBodyData = st.onBodyData

proc beginConn(st: HttpReq, client: HttpClientBase, conn: Connection,
               reuseParser: HttpParser = nil) =
  ## Run the prepared request on `conn` (fresh or reused from the pool).
  st.conn = conn
  if not st.active:
    conn.close()
    return
  # A pooled CONNECT tunnel is already established (ssl != nil): reuse it
  # directly. Fresh connections (and plain sockets) need the handshake.
  st.proxyPending = st.needsProxyTunnel and conn.ssl == nil
  if st.proxyPending:
    # HTTPS-over-proxy: the CONNECT head goes out now; the real request
    # (and TLS) wait for the proxy's 200, handled in onFdImpl.
    discard conn.send(st.proxyHead)
    if conn.state != Connected:
      if retryFresh(st, client):
        connectFresh(st, client, conn.loop)
      else:
        failReq(st, client, "proxy connection closed")
      return
  else:
    try:
      if st.tlsNeeded:
        if client.tlsCtx == nil:
          failReq(st, client, "https requested but no tlsCtx configured")
          return
        conn.wrapTls(client.tlsCtx, st.tlsHost)
    except SslError:
      failReq(st, client, getCurrentExceptionMsg())
      return
    initClientParser(st, client, reuseParser)
    discard conn.send(st.reqHeaders)
    if st.bodyBytes.len > 0:
      discard conn.send(st.bodyBytes)
    if conn.state != Connected:
      # The connection died while writing the request (send closes it
      # internally). Registering its (now invalid) fd would wait on events
      # that never arrive, so retry or fail here instead. A pooled connection
      # the server already killed is the classic case — the server never saw
      # these bytes, so one transparent retry on a fresh connection is safe.
      if retryFresh(st, client):
        connectFresh(st, client, conn.loop)
      else:
        failReq(st, client, "connection closed while writing")
      return
    if conn.tlsState != TlsHandshaking:
      # No handshake pending (plain TCP, pooled TLS, UDS): app bytes flow.
      st.connectDone = true
      rearm(st, client)
  # Re-register in place: register() already replaces the existing watcher.
  # Unregistering first would trash the fd state while its WSARecv is still
  # in flight on Windows/IOCP, so the response bytes would land in the trash
  # and be lost (hanging the request or surfacing as a connection error).
  conn.loop.register(conn.fd.int, {Read, Write}, edgeTriggered = true,
    callback = proc(fd: int, ev: set[EventType]) =
      onFdImpl(st, client, fd, ev))

proc connectFresh(st: HttpReq, client: HttpClientBase, loop: Loop) =
  ## Open a new TCP/UDS connection and run the request on it.
  when not defined(windows):
    if st.key.uds.len > 0:
      try:
        loop.connectUnix(st.key.uds,
          onConnect = proc(conn: Connection) =
            beginConn(st, client, conn)
          ,
          onData = proc(conn: Connection, data: openArray[byte]) = discard,
          onClose = proc(conn: Connection) =
            if st.active:
              failReq(st, client, "connection closed during request")
        )
      except NetError as e:
        failReq(st, client, e.msg)
      return

  loop.connect(st.key.host, st.key.port,
    onConnect = proc(conn: Connection) =
      beginConn(st, client, conn)
    ,
    onData = proc(conn: Connection, data: openArray[byte]) = discard,
    onClose = proc(conn: Connection) =
      if st.active:
        if retryFresh(st, client):
          connectFresh(st, client, loop)
        else:
          failReq(st, client, "connection closed during request")
    ,
    onError = proc(err: string) =
      if st.active:
        failReq(st, client, err)
  )

proc proxyHandshakeBytes(st: HttpReq, client: HttpClientBase): bool =
  ## Consume the proxy's CONNECT response with raw reads (no parser: the
  ## bytes belong to the tunnel negotiation, not the origin response).
  ## Returns true once the tunnel is established and `wrapTls` applied;
  ## false to wait for more data. Fails the request on protocol errors.
  ## The server cannot send tunnel bytes before our ClientHello, so
  ## consuming reads are safe: nothing after the header block can be
  ## misattributed (a non-empty trailer is rejected).
  let conn = st.conn
  var buf: array[4096, byte]
  var n: int
  when defined(windows):
    n = conn.loop.platform.getReadData(conn.fd.int,
      cast[ptr UncheckedArray[byte]](addr buf[0]), buf.len)
    if n < 0:
      return false  # completion in flight; the next one re-enters here
  else:
    while true:
      n = sockRecv(conn.fd, addr buf[0], buf.len)
      if n < 0:
        if sockWouldBlock():
          return false
        if sockInterrupted():
          continue
        failReq(st, client, "proxy read error")
        return false
      break
  if n == 0:
    failReq(st, client, "proxy closed the connection")
    return false
  if st.proxyBuf.len + n > 16384:
    failReq(st, client, "proxy response too large")
    return false
  let off = st.proxyBuf.len
  st.proxyBuf.setLen(off + n)
  copyMem(addr st.proxyBuf[off], addr buf[0], n)
  let term = st.proxyBuf.find("\r\n\r\n")
  if term < 0:
    return false
  if st.proxyBuf.len > term + 4:
    failReq(st, client, "proxy sent data after CONNECT headers")
    return false
  let head = st.proxyBuf[0 ..< term]
  let sp = head.find(' ')
  if sp < 0 or not head.startsWith("HTTP/1."):
    failReq(st, client, "invalid proxy response")
    return false
  var code = -1
  if head.len >= sp + 4:
    try:
      code = parseInt(head[sp + 1 ..< sp + 4])
    except ValueError:
      discard
  if code == 407:
    failReq(st, client, "proxy authentication required (407)")
    return false
  if code != 200:
    failReq(st, client, "proxy CONNECT failed with status " & $code)
    return false
  st.proxyBuf.setLen(0)
  try:
    conn.wrapTls(client.tlsCtx, st.tlsHost)
  except SslError as e:
    failReq(st, client, e.msg)
    return false
  st.proxyPending = false
  true

proc onFdImpl(st: HttpReq, client: HttpClientBase, fd: int,
              ev: set[EventType]) =
  let conn = st.conn
  if conn == nil or conn.state != Connected:
    return
  if not st.active:
    # Stale event on an idle/pooled connection. A pure-Write event is not
    # death: kqueue reports Read and Write as separate events, so the
    # writability that was current when the response completed is still
    # dispatched after pooling (epoll coalesces both into one event and never
    # hits this). Only Error/Hup/Read can mean the server closed the idle
    # socket — a trailing Write must be ignored or every pooled connection
    # risks immediate eviction on macOS/BSD.
    if Read in ev or Hup in ev or Error in ev:
      if client.pool.removeFromPool(conn):
        conn.close()
    return
  if Error in ev and Read notin ev:
    if retryFresh(st, client):
      # Error on a pooled connection the server already killed (RST with
      # nothing to drain) — same stale keep-alive race as the EOF path.
      connectFresh(st, client, conn.loop)
    else:
      failReq(st, client, "connection error")
    return
  if st.proxyPending and (Read in ev or Hup in ev):
    # CONNECT handshake in flight: raw bytes belong to the proxy, not the
    # origin parser. On 200 the tunnel is ready — send the real request
    # through it (queued into TLS/sockets by send as usual).
    if proxyHandshakeBytes(st, client):
      initClientParser(st, client)
      discard conn.send(st.reqHeaders)
      if st.bodyBytes.len > 0:
        discard conn.send(st.bodyBytes)
      if conn.state != Connected:
        if retryFresh(st, client):
          connectFresh(st, client, conn.loop)
        else:
          failReq(st, client, "connection closed after CONNECT")
    return
  if conn.tlsState == TlsHandshaking:
    if not conn.driveHandshake():
      return
  if not st.connectDone and not st.proxyPending and
     conn.tlsState != TlsHandshaking:
    # TCP + TLS + tunnel all up: switch from the connect window to the
    # total/read schedule.
    st.connectDone = true
    rearm(st, client)
  if Write in ev:
    if conn.flushWriteBuffer():
      if conn.state != Connected:
        if retryFresh(st, client):
          # Send-side death on a pooled connection (RST processed at flush
          # time) — the server never saw these bytes, so resending is safe.
          connectFresh(st, client, conn.loop)
        else:
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
        if conn.tlsState == TlsActive:
          # TLS connection (https): read decrypted plaintext. During the
          # handshake (TlsHandshaking) we never reach here — driveHandshake
          # above returns early — so the socket BIO owns those bytes.
          n = conn.tlsRead(addr buf[0], buf.len)
          if n == -2:
            break
        else:
          n = sockRecv(conn.fd, addr buf[0], buf.len)
      if n > 0:
        if st.readTimeoutMs > 0:
          rearm(st, client)  # response progress: restart the inactivity window
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
        if st.parser.headersDone and st.parser.getStatusCode() == Http100:
          # Interim "100 Continue" (e.g. after we sent Expect: 100-continue):
          # not the final answer. Drop it, replay any already-buffered bytes,
          # and keep reading until the real response arrives.
          st.parser.resetForNext()
          st.parser.tryAdvance()
          if st.parser.isError():
            failReq(st, client, "invalid HTTP response")
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
        elif retryFresh(st, client):
          # Pooled connection was closed by the server between requests and
          # nothing came back yet — silently open a fresh connection.
          connectFresh(st, client, conn.loop)
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
          if retryFresh(st, client):
            # Recv-side death on a pooled connection (RST, e.g. server-side
            # linger-0 close) with nothing received yet — retry transparently.
            connectFresh(st, client, conn.loop)
          else:
            failReq(st, client, "recv error")
          return
    if (Hup in ev or Error in ev) and conn.state == Connected and st.active:
      if st.parser.phase == PhaseComplete:
        if st.pendingCloseDelimited or st.closeDelimitedResponse():
          st.parser.finalizeCloseDelimited()
        deliverReq(st, client)
      elif retryFresh(st, client):
        connectFresh(st, client, conn.loop)
      else:
        failReq(st, client, "connection closed before response completed")

proc rearm(st: HttpReq, client: HttpClientBase) =
  ## (Re)arm the single request timer to the nearest applicable deadline:
  ## total first, then the connect window (until app bytes flow) or the
  ## read-inactivity window. No timer when nothing is configured.
  if st.timer != TimerId(0):
    st.loop.cancelTimer(st.timer)
    st.timer = TimerId(0)
  if not st.active:
    return
  let now = monoMs()
  var best = int64.high
  var any = false
  if st.deadlineTotalMs > 0:
    best = min(best, st.deadlineTotalMs - now)
    any = true
  if not st.connectDone:
    if st.connectTimeoutMs > 0:
      best = min(best, st.connectTimeoutMs.int64)
      any = true
  elif st.readTimeoutMs > 0:
    best = min(best, st.readTimeoutMs.int64)
    any = true
  if not any:
    return
  if best < 0:
    best = 0
  st.timer = st.loop.addTimer(best.int) do (id: int):
    if not st.active:
      return
    let now2 = monoMs()
    if st.deadlineTotalMs > 0 and now2 >= st.deadlineTotalMs:
      failReq(st, client, "request timed out")
    elif not st.connectDone:
      failReq(st, client, "connect timed out")
    else:
      failReq(st, client, "read timed out")

proc requestImpl*(client: HttpClientBase, loop: Loop, meth: HttpMethod,
                 url: string, body: openArray[byte],
                 headers: openArray[(string, string)],
                 unixSocket: string, timeoutOverride: int,
                 onResponse: proc(res: HttpClientResponse) {.closure.},
                 onBodyData: HttpBodyCallback,
                 onError: proc(err: string) {.closure.}): HttpReq =
  let parsed = parseHttpUrl(url)
  let timeout = if timeoutOverride < 0: client.timeoutMs else: timeoutOverride
  let tlsNeeded = parsed.scheme == "https"
  # Proxy resolution (client policy; "" = direct).
  var proxyHost = ""
  var proxyPort = 0
  var proxyAuth = ""
  if client.proxyUrl.len > 0:
    if unixSocket.len > 0:
      raise newException(HttpError, "proxy with unixSocket is not supported")
    (proxyHost, proxyPort, proxyAuth) = parseProxyUrl(client.proxyUrl)
    if tlsNeeded and client.tlsCtx == nil:
      raise newException(HttpError,
        "https proxy tunnel requested but no tlsCtx configured")
  let useProxy = proxyHost.len > 0
  let needsTunnel = useProxy and tlsNeeded
  let targetAuth = authorityHost(parsed.host) &
    (if (parsed.scheme == "http" and parsed.port == 80) or
        (parsed.scheme == "https" and parsed.port == 443): ""
     else: ":" & $parsed.port)
  let proxyIdent =
    if not useProxy: ""
    elif not needsTunnel: proxyHost.toLowerAscii() & ":" & $proxyPort
    else: proxyHost.toLowerAscii() & ":" & $proxyPort & ">" &
          parsed.host.toLowerAscii() & ":" & $parsed.port
  let key: PoolKey = (
    host: (if useProxy: proxyHost.toLowerAscii() else: parsed.host.toLowerAscii()),
    port: (if useProxy: proxyPort else: parsed.port),
    tls: tlsNeeded and not useProxy,
    uds: unixSocket,
    proxy: proxyIdent,
  )
  let requestTarget =
    if useProxy and not needsTunnel:
      parsed.scheme & "://" & targetAuth & parsed.path
    else:
      parsed.path
  var allHeaders = @headers
  if proxyAuth.len > 0 and not needsTunnel:
    # Hop-by-hop credentials for the proxy itself; never send them
    # end-to-end inside a CONNECT tunnel (the tunneled request keeps only
    # the origin's headers — the CONNECT head carries Proxy-Authorization).
    allHeaders.insert(("Proxy-Authorization", proxyAuth), 0)
  let targetHostPort = authorityHost(parsed.host) & ":" & $parsed.port
  var proxyHead = ""
  if needsTunnel:
    proxyHead = "CONNECT " & targetHostPort & " HTTP/1.1\r\nHost: " &
      targetHostPort & "\r\n"
    if proxyAuth.len > 0:
      proxyHead.add("Proxy-Authorization: " & proxyAuth & "\r\n")
    proxyHead.add("\r\n")

  let st = HttpReq(
    client: client,
    onResponse: onResponse,
    onBodyData: onBodyData,
    onError: onError,
    active: true,
    timer: TimerId(0),
    key: key,
    tlsNeeded: tlsNeeded,
    tlsHost: parsed.host.toLowerAscii(),
    needsProxyTunnel: needsTunnel,
    proxyHead: proxyHead,
    reqHeaders: buildRequestHeaders(client, meth, requestTarget, targetAuth,
                                    body.len, allHeaders),
    bodyBytes: @body,
    noBodyExpected: meth == HttpHead,
    loop: loop,
    startMs: monoMs(),
    connectTimeoutMs: client.connectTimeoutMs,
    readTimeoutMs: client.readTimeoutMs,
  )
  if timeout > 0:
    st.deadlineTotalMs = st.startMs + timeout.int64
  # Connect-phase deadline (total and/or connect window); rearm() switches
  # to the total/read schedule once app bytes flow.
  rearm(st, client)

  # Reuse a pooled keep-alive connection for this origin when available.
  if client.keepAlive:
    let pc = client.pool.pop(loop, key)
    if pc.conn != nil:
      st.cameFromPool = true
      beginConn(st, client, pc.conn, pc.parser)
      return st

  connectFresh(st, client, loop)
  st
# ── Policy wrapper: cookies + redirects ─────────────────

proc injectCookieHeaders(client: HttpClientBase, url: string,
    headers: openArray[(string, string)]): seq[(string, string)] =
  ## Copy `headers`, appending the jar's `Cookie` header for `url`
  ## (merged with a user-supplied one). Raises HttpError on invalid `url`.
  result = @headers
  if client.cookieJar == nil:
    return
  let ch = client.cookieJar.cookieHeaderForUrl(url)
  if ch.len == 0:
    return
  for i in 0 ..< result.len:
    if result[i][0].toLowerAscii() == "cookie":
      result[i][1] = result[i][1] & "; " & ch
      return
  result.add(("Cookie", ch))

proc extractResponseCookies(client: HttpClientBase, url: string,
    res: HttpClientResponse) =
  ## Store `res` cookies into the jar. Never raises (a malformed cookie
  ## must not fail the request).
  if client.cookieJar == nil:
    return
  try:
    client.cookieJar.storeResponseCookies(url, res)
  except CatchableError:
    discard

proc redirectHop(client: HttpClientBase, meth: HttpMethod, url: string,
    body: openArray[byte], headers: openArray[(string, string)],
    res: HttpClientResponse, hopsLeft: int):
    tuple[follow: bool, meth: HttpMethod, url: string, body: seq[byte],
      headers: seq[(string, string)]] =
  ## One redirect step: returns follow=false when `res` is not a followed
  ## 3xx (or hops are exhausted). Raises HttpError on invalid `Location`.
  if hopsLeft <= 0 or res.getStatusCode() notin redirectCodes:
    return (false, meth, "", @[], @[])
  let loc = res.getHeaderValue("location")
  if loc.len == 0:
    return (false, meth, "", @[], @[])
  let nextUrl = resolveRedirectUrl(url, loc)
  if nextUrl.len == 0:
    return (false, meth, "", @[], @[])
  let (nmeth, nbody, nheaders) = rewriteForRedirect(meth,
    res.getStatusCode(), body, headers, url, nextUrl)
  (true, nmeth, nextUrl, nbody, nheaders)

proc doRequest(client: HttpClientBase, loop: Loop, meth: HttpMethod,
    url: string, body: openArray[byte], headers: openArray[(string, string)],
    unixSocket: string, timeoutMs: int, redirectsLeft: int,
    onResponse: proc(res: HttpClientResponse) {.closure.},
    onBodyData: HttpBodyCallback,
    onError: proc(err: string) {.closure.}): HttpReq =
  ## Async-path single request with client policy: cookie inject/extract
  ## around the call and 3xx redirect chasing after it. Recursion here is
  ## safe — `requestImpl` never blocks, so no poll loop ever nests.
  let bodySeq = @body  # owned copy: the response closure below may re-send it
  var effHeaders: seq[(string, string)]
  try:
    effHeaders = injectCookieHeaders(client, url, headers)
  except HttpError as e:
    onError(e.msg)
    return nil
  try:
    result = requestImpl(client, loop, meth, url, bodySeq, effHeaders,
        unixSocket, timeoutMs,
      onResponse = proc(res: HttpClientResponse) =
        extractResponseCookies(client, url, res)
        var hop: tuple[follow: bool, meth: HttpMethod, url: string,
          body: seq[byte], headers: seq[(string, string)]]
        try:
          hop = redirectHop(client, meth, url, bodySeq, effHeaders, res,
            redirectsLeft)
        except HttpError as e:
          onError(e.msg)
          return
        if hop.follow:
          discard doRequest(client, loop, hop.meth, hop.url, hop.body,
            hop.headers, unixSocket, timeoutMs, redirectsLeft - 1,
            onResponse, onBodyData, onError)
          return
        onResponse(res)
      ,
      onBodyData = onBodyData,
      onError = onError)
  except HttpError as e:
    onError(e.msg)
    return nil

# ── Response accessors ───────────────────────────────────────────────────────

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
                         maxBodySize: int = DefaultMaxResponseBody,
                         maxIdlePerHost: int = DefaultMaxIdlePerHost,
                         maxIdleTotal: int = DefaultMaxIdleTotal,
                         idleTimeoutMs: int = DefaultIdleTimeoutMs,
                         maxRedirects: int = 0,
                         proxyUrl: string = "",
                         connectTimeoutMs: int = 0,
                         readTimeoutMs: int = 0): AsyncHttpClient =
  ## Create an async HTTP client with its own event loop. Await the request
  ## methods from an `async` proc with asyncdispatch.
  ##
  ## Pooling knobs: `maxIdlePerHost`/`maxIdleTotal` cap idle keep-alive
  ## connections; `idleTimeoutMs` retires idle connections lazily (0 disables).
  ##
  ## `maxRedirects` follows 301/302/303/307/308 (0 = return them as-is).
  ## Attach `client.cookieJar = newCookieJar()` to persist cookies.
  AsyncHttpClient(
    loop: newLoop(),
    tlsCtx: tlsCtx,
    keepAlive: keepAlive,
    timeoutMs: timeoutMs,
    maxBodySize: maxBodySize,
    defaultHeaders: @[],
    pool: newHttpConnPool(maxIdlePerHost, maxIdleTotal, idleTimeoutMs),
    maxRedirects: maxRedirects,
    proxyUrl: proxyUrl,
    connectTimeoutMs: connectTimeoutMs,
    readTimeoutMs: readTimeoutMs,
  )

proc newHttpClient*(tlsCtx: SslContext = nil, keepAlive: bool = true,
                    timeoutMs: int = 0,
                    maxBodySize: int = DefaultMaxResponseBody,
                    maxIdlePerHost: int = DefaultMaxIdlePerHost,
                    maxIdleTotal: int = DefaultMaxIdleTotal,
                    idleTimeoutMs: int = DefaultIdleTimeoutMs,
                    maxRedirects: int = 0,
                    proxyUrl: string = "",
                    connectTimeoutMs: int = 0,
                    readTimeoutMs: int = 0): HttpClient =
  ## Blocking HTTP client. `maxRedirects` follows 301/302/303/307/308
  ## (0 = return them as-is). Attach `client.cookieJar = newCookieJar()`
  ## to persist cookies.
  HttpClient(
    syncLoop: newLoop(),
    tlsCtx: tlsCtx,
    keepAlive: keepAlive,
    timeoutMs: timeoutMs,
    maxBodySize: maxBodySize,
    defaultHeaders: @[],
    pool: newHttpConnPool(maxIdlePerHost, maxIdleTotal, idleTimeoutMs),
    maxRedirects: maxRedirects,
    proxyUrl: proxyUrl,
    connectTimeoutMs: connectTimeoutMs,
    readTimeoutMs: readTimeoutMs,
  )

proc getLoop*(client: HttpClient): Loop {.inline.} =
  ## The private loop the sync client blocks on. Exposed so other subsystems
  ## (e.g. a test server) can be hosted on the same loop and driven by the
  ## client's `poll` while a request is in flight.
  client.syncLoop

func idleConnections*(client: HttpClientBase): int {.inline.} =
  ## Number of idle keep-alive connections currently held in the pool.

  client.pool.totalIdle

proc close*(client: AsyncHttpClient) =
  ## Close all pooled keep-alive connections and the client's event loop.
  client.pool.closeAll()
  client.loop.close()

proc close*(client: HttpClient) =
  ## Close all pooled keep-alive connections and the client's event loop.
  client.pool.closeAll()
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
    discard doRequest(client, client.loop, meth, url, body, headers,
                        unixSocket, timeoutMs,
                        min(client.maxRedirects, MaxRedirectHops),
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
  ## Redirect hops run as an explicit loop of single-shot requests (never
  ## nested poll loops).
  var cmeth = meth
  var curl = url
  var cbody = @body
  var cheaders = @headers
  var hops = min(client.maxRedirects, MaxRedirectHops)
  while true:
    let effHeaders = injectCookieHeaders(client, curl, cheaders)
    var done = false
    var resp: HttpClientResponse
    var errMsg = ""
    discard requestImpl(client, client.syncLoop, cmeth, curl, cbody,
        effHeaders, unixSocket, timeoutMs,
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
    extractResponseCookies(client, curl, resp)
    let hop = redirectHop(client, cmeth, curl, cbody, cheaders, resp, hops)
    if not hop.follow:
      return resp
    cmeth = hop.meth
    curl = hop.url
    cbody = hop.body
    cheaders = hop.headers
    dec hops

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
