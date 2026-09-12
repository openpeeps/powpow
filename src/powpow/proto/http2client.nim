# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/proto/http2client.nim — HTTP/2 client (RFC 7540).
##
## `H2ClientConn` is one multiplexed connection: many concurrent `request`
## calls share it, each on its own stream with its own callback. Flow
## control, HPACK, and framing ride on `H2Conn` (client role); this module
## adds connection lifecycle (cleartext preface, TLS+ALPN), per-request
## queueing while the peer's SETTINGS are unknown, and graceful GOAWAY
## draining.
##
## `H2ClientPool` keys connections by origin `(host, port, tls)` and
## multiplexes requests across the least-loaded one, opening more (up to
## `maxPerOrigin`) as needed. Overflow waits on the least-loaded
## connection's queue — natural backpressure, no extra timers.

import std/[tables, strutils]

import ../net/tcp
import ../net/tls
import ../loop
import ./http2
import ./hpack
import ./http2conn

type
  H2WaitingReq = object
    meth, path, scheme, authority: string
    headers: seq[(string, string)]
    body: seq[byte]
    cb: H2ClientCallback

  H2ClientConn* = ref object
    loop*: Loop
    conn*: Connection
    h2*: H2Conn
    host*: string
    port*: int
    tls*: bool
    ready*: bool
    closed*: bool
    waiting*: seq[H2WaitingReq]
    onCloseCb*: proc(c: H2ClientConn) {.closure.}

  H2PoolKey = tuple[host: string, port: int, tls: bool]

  H2ClientPool* = ref object
    loop*: Loop
    tlsCtx*: SslContext
    maxPerOrigin*: int
    maxStreamsHint*: int
    conns*: Table[H2PoolKey, seq[H2ClientConn]]

const H2ClientMaxStreamsHint* = 100

proc failStreams(c: H2ClientConn, err: string) =
  ## Deliver `err` to every in-flight stream callback (e.g. TCP dropped).
  if c.h2 == nil:
    return
  for _, st in c.h2.streams.mpairs:
    let cb = st.clientCb
    st.clientCb = nil
    if cb != nil:
      cb(H2ClientResponse(), err)
  c.h2.streams.clear()
  c.h2.openCount = 0
  c.h2.pending.setLen(0)

proc close*(c: H2ClientConn) =
  if c.closed:
    return
  c.closed = true
  for w in c.waiting:
    if w.cb != nil:
      w.cb(H2ClientResponse(), "closed")
  c.waiting.setLen(0)
  c.failStreams("closed")
  if c.h2 != nil and not c.h2.goawaySent and not c.h2.h2Closed():
    c.h2.goawaySent = true
    discard c.conn.send(encodeGoaway(c.h2.lastPeerSid, H2NoError))
  c.conn.close()

proc failWaiting(c: H2ClientConn, err: string) =
  for w in c.waiting:
    if w.cb != nil:
      w.cb(H2ClientResponse(), err)
  c.waiting.setLen(0)

proc tryWaiting(c: H2ClientConn) =
  ## Open queued requests while the connection has capacity.
  if c.closed or not c.ready or c.h2 == nil:
    return
  var i = 0
  while i < c.waiting.len:
    let w = c.waiting[i]
    var hs = @[HpackHeader(name: ":method", value: w.meth),
               HpackHeader(name: ":scheme", value: w.scheme),
               HpackHeader(name: ":path", value: w.path),
               HpackHeader(name: ":authority", value: w.authority)]
    for (n, v) in w.headers:
      hs.add(HpackHeader(name: n.toLowerAscii(), value: v))
    let sid = c.h2.openClientStream(hs, w.body, true, w.cb)
    if sid < 0:
      inc i  # still no capacity; later requests wait behind it
    else:
      c.waiting.delete(i)

proc request*(c: H2ClientConn, meth, path: string,
              headers: openArray[(string, string)], body: seq[byte],
              cb: H2ClientCallback) =
  ## Multiplexed request. The callback fires exactly once — with the full
  ## response, or with `err` when the stream is reset, refused, or the
  ## connection dies first.
  let scheme = if c.tls: "https" else: "http"
  if c.closed:
    cb(H2ClientResponse(), "closed")
    return
  var hs = @[HpackHeader(name: ":method", value: meth),
             HpackHeader(name: ":scheme", value: scheme),
             HpackHeader(name: ":path", value: path),
             HpackHeader(name: ":authority", value: c.host)]
  for (n, v) in headers:
    hs.add(HpackHeader(name: n.toLowerAscii(), value: v))
  if c.ready and c.h2 != nil:
    let sid = c.h2.openClientStream(hs, body, true, cb)
    if sid >= 0:
      return
    if c.h2.h2Draining() or c.h2.h2Closed():
      cb(H2ClientResponse(), "goaway")
      return
  c.waiting.add(H2WaitingReq(meth: meth, path: path, scheme: scheme,
                             authority: c.host, headers: @headers,
                             body: body, cb: cb))

proc request*(c: H2ClientConn, meth, path: string,
              headers: openArray[(string, string)], body: string,
              cb: H2ClientCallback) =
  var b = newSeq[byte](body.len)
  for i, ch in body:
    b[i] = byte(ch)
  c.request(meth, path, headers, b, cb)

proc feedClient(c: H2ClientConn, data: openArray[byte]) =
  when not defined(windows):
    if c.tls:
      if not c.conn.isTlsActive():
        return
      if not c.h2.alpnChecked:
        c.h2.alpnChecked = true
        if c.conn.alpnSelected() != "h2":
          c.failWaiting("alpn mismatch")
          c.close()
          return
  c.h2.feedH2(data)

proc finishConnect(c: H2ClientConn) =
  c.h2.startClientPreface()
  c.ready = true
  c.tryWaiting()

proc connectH2*(loop: Loop, host: string, port: int,
                onConn: proc(c: H2ClientConn,
                             err: string) {.closure.}) =
  ## Open a cleartext (h2c, prior knowledge) connection.
  var holder: H2ClientConn
  holder = H2ClientConn(loop: loop, host: host, port: port, tls: false,
                        ready: false, closed: false, waiting: @[])
  let c = holder
  loop.connect(host, port,
    onConnect = proc(conn: Connection) =
      c.conn = conn
      c.h2 = newH2Conn(conn, H2ClientRole, nil)
      c.h2.onSettingsApplied = proc(h: H2Conn) {.closure.} =
        c.tryWaiting()
      c.finishConnect()
      onConn(c, "")
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      c.feedClient(data)
    ,
    onClose = proc(conn: Connection) =
      if not c.closed:
        c.closed = true
        c.failWaiting("closed")
        c.failStreams("closed")
        if c.onCloseCb != nil:
          c.onCloseCb(c)
    ,
    onError = proc(err: string) =
      if not c.ready and not c.closed:
        c.closed = true
        c.failWaiting(err)
        onConn(c, err)
  )

proc connectH2Tls*(loop: Loop, host: string, port: int, tlsCtx: SslContext,
                   onConn: proc(c: H2ClientConn,
                                err: string) {.closure.}) =
  ## Open an `h2` (TLS + ALPN) connection. `tlsCtx` must advertise `h2`
  ## (call `setAlpnProtocols(["h2"])`) — anything else fails the connect.
  when defined(windows):
    onConn(nil, "TLS is not supported on Windows")
  else:
    var holder: H2ClientConn
    holder = H2ClientConn(loop: loop, host: host, port: port, tls: true,
                          ready: false, closed: false, waiting: @[])
    let c = holder
    loop.connect(host, port,
      onConnect = proc(conn: Connection) =
        c.conn = conn
        conn.wrapTls(tlsCtx, serverName = host)
        c.h2 = newH2Conn(conn, H2ClientRole, nil)
        c.h2.onSettingsApplied = proc(h: H2Conn) {.closure.} =
          c.tryWaiting()
        c.finishConnect()
        onConn(c, "")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        c.feedClient(data)
      ,
      onClose = proc(conn: Connection) =
        if not c.closed:
          c.closed = true
          c.failWaiting("closed")
          c.failStreams("closed")
          if c.onCloseCb != nil:
            c.onCloseCb(c)
      ,
      onError = proc(err: string) =
        if not c.ready and not c.closed:
          c.closed = true
          c.failWaiting(err)
          onConn(c, err)
    )

# ── Origin pool ───────────────────────────────────────────────────────

proc newH2ClientPool*(loop: Loop, tlsCtx: SslContext = nil,
                      maxPerOrigin = 4): H2ClientPool =
  H2ClientPool(loop: loop, tlsCtx: tlsCtx, maxPerOrigin: maxPerOrigin,
               maxStreamsHint: H2ClientMaxStreamsHint,
               conns: initTable[H2PoolKey, seq[H2ClientConn]]())

proc poolPrune(pool: H2ClientPool, key: H2PoolKey) =
  if not pool.conns.hasKey(key):
    return
  var alive: seq[H2ClientConn] = @[]
  for c in pool.conns[key]:
    if not c.closed:
      alive.add(c)
  if alive.len == 0:
    pool.conns.del(key)
  else:
    pool.conns[key] = alive

proc request*(pool: H2ClientPool, host: string, port: int, tls: bool,
              meth, path: string, headers: openArray[(string, string)],
              body: seq[byte], cb: H2ClientCallback) =
  ## One multiplexed request through the pool. Connections are shared per
  ## origin; overflow waits on the least-loaded connection.
  let key: H2PoolKey = (host, port, tls)
  pool.poolPrune(key)
  var best: H2ClientConn = nil
  var bestLoad = high(int)
  var total = 0
  if pool.conns.hasKey(key):
    for c in pool.conns[key]:
      inc total
      if c.closed or not c.ready or c.h2 == nil:
        continue
      if c.h2.goawayReceived:
        continue
      let load = c.h2.openCount + c.waiting.len
      let cap = min(c.h2.peerMaxConcurrent, pool.maxStreamsHint)
      if load < cap and load < bestLoad:
        best = c
        bestLoad = load
  if best != nil:
    best.request(meth, path, headers, body, cb)
    return
  if total < pool.maxPerOrigin:
    # Open another connection for this origin; the request rides it.
    # Materialize capturables: openArray params cannot be closed over.
    let loop = pool.loop
    let tlsCtx = pool.tlsCtx
    let hdrs = @headers
    proc onConn(c: H2ClientConn, err: string) {.closure.} =
      if err != "" or c == nil:
        cb(H2ClientResponse(), if err != "": err else: "connect failed")
        return
      pool.poolPrune(key)
      if not pool.conns.hasKey(key):
        pool.conns[key] = @[]
      pool.conns[key].add(c)
      c.onCloseCb = proc(closed: H2ClientConn) {.closure.} =
        pool.poolPrune(key)
      c.request(meth, path, hdrs, body, cb)
    if tls:
      if tlsCtx == nil:
        cb(H2ClientResponse(), "no TLS context for https origin")
        return
      connectH2Tls(loop, host, port, tlsCtx, onConn)
    else:
      connectH2(loop, host, port, onConn)
    return
  # At capacity: wait on the least-loaded live connection.
  var waitOn: H2ClientConn = nil
  var waitLoad = high(int)
  if pool.conns.hasKey(key):
    for c in pool.conns[key]:
      if c.closed:
        continue
      if c.waiting.len < waitLoad:
        waitOn = c
        waitLoad = c.waiting.len
  if waitOn != nil:
    let scheme = if tls: "https" else: "http"
    waitOn.waiting.add(H2WaitingReq(meth: meth, path: path, scheme: scheme,
                                    authority: host, headers: @headers,
                                    body: body, cb: cb))
  else:
    cb(H2ClientResponse(), "pool exhausted")

proc request*(pool: H2ClientPool, host: string, port: int, tls: bool,
              meth, path: string, headers: openArray[(string, string)],
              body: string, cb: H2ClientCallback) =
  var b = newSeq[byte](body.len)
  for i, ch in body:
    b[i] = byte(ch)
  pool.request(host, port, tls, meth, path, headers, b, cb)

proc close*(pool: H2ClientPool) =
  for _, seqConns in pool.conns:
    for c in seqConns:
      c.close()
  pool.conns.clear()
