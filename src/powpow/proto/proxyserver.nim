# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/proto/proxyserver.nim — High-level TCP reverse proxy.
##
## A `ProxyServer` owns its `Loop` + `seq[TcpServer]` frontends + pair state,
## just like `HttpServer`. The low-level `examples/tcp_proxy.nim` hand-rolls
## `newTcpServer` + `Loop.connect` + `Table[int,ProxyPair]` + `pending` +
## `teardown`. This module hides that behind friendly `proxy.onXxx` setters.
##
## ### Usage:
##   ```nim
##   import powpow/proto/proxyserver
##
##   let proxy = newProxyServer()             # owns its Loop
##   # or: let proxy = newProxyServer(loop)   # use an existing Loop
##   # or: let proxy = newProxyServer("127.0.0.1", 9001)
##
##   proxy.onConnect(proc(pair: ProxyPair) {.gcsafe.} =
##     echo "client ", pair.client.fd.int, " connected"
##   )
##   proxy.onUpstreamConnect(proc(pair: ProxyPair) {.gcsafe.} =
##     echo "proxied ", pair.client.fd.int, " -> ", pair.upstream.fd.int
##   )
##   proxy.onData(proc(pair: ProxyPair, dir: ProxyDir,
##                     data: openArray[byte]) {.gcsafe.} =
##     echo dir, " ", data.len, " bytes"
##   )
##   proxy.onClose(proc(pair: ProxyPair, dir: ProxyDir) {.gcsafe.} =
##     echo "closed from ", dir
##   )
##   proxy.onError(proc(pair: ProxyPair, err: string) {.gcsafe.} =
##     echo "error: ", err
##   )
##
##   proxy.setUpstream("127.0.0.1", 9001)     # static upstream
##   proxy.listen("0.0.0.0", 9020)            # additive, multi-port ready
##   proxy.listen("0.0.0.0", 9021)
##   proxy.start(Port(9020), Port(9021))      # blocks: listen + loop.run()
##   # or: proxy.getLoop().run() after manual listen
##   ```
##
## The proxy is transparent: bytes flow both ways, buffered while the upstream
## connects, and closing either side tears down the pair. Callbacks are
## notifications — forwarding happens automatically before they fire. Use
## `pair.client.send` / `pair.upstream.send` inside callbacks for injection.

import std/[tables, sequtils]
import std/net except IpAddress, IpAddressFamily
import ../loop
import ../types
import ../net/tcp

export Port
export loop
export tcp
export types

# ── Types ────────────────────────────────────────────────────────────────────

type
  ProxyDir* = enum
    FromClient    ## data flowing client -> upstream
    FromUpstream  ## data flowing upstream -> client

  ProxyPair* = ref object
    ## A proxied connection pair. Exposed to callbacks; both `client` and
    ## `upstream` are the raw `Connection` objects so callers can
    ## `pair.client.getClientIp()`, `pair.client.send(...)`, etc.
    id*:       int
    client*:   Connection
    upstream*: Connection
    pending*:  seq[byte]  ## client bytes buffered until upstream connects

  OnProxyConnect* = proc(pair: ProxyPair) {.gcsafe.}
    ## Client accepted, before upstream connect is attempted.

  OnProxyUpstreamConnect* = proc(pair: ProxyPair) {.gcsafe.}
    ## Upstream successfully connected; `pair.upstream` is now set.

  OnProxyData* = proc(pair: ProxyPair, dir: ProxyDir,
                      data: openArray[byte]) {.gcsafe.}
    ## Data flowing in `dir`. Forwarding happens automatically; this is a
    ## notification hook (e.g. for logging / metrics / injection).

  OnProxyClose* = proc(pair: ProxyPair, dir: ProxyDir) {.gcsafe.}
    ## Either side of `pair` closed. `dir` indicates which side initiated.

  OnProxyError* = proc(pair: ProxyPair, err: string) {.gcsafe.}
    ## Upstream connect / DNS error. `pair` always has `client` set.

  ProxyServer* = ref object
    loop: Loop
    frontends: seq[TcpServer]
    upstreamHost*: string
    upstreamPort*: int
    upstreamUnixPath*: string
    useUnix*: bool
    pairs: Table[int, ProxyPair]
    byUpstream: Table[int, int]
    nextId: int
    maxPending*: int
    maxConnections*: int
    closed: bool
    ownsLoop: bool
    # callbacks
    onConnectCb: OnProxyConnect
    onUpstreamConnectCb: OnProxyUpstreamConnect
    onDataCb: OnProxyData
    onClientDataCb: OnProxyData
    onUpstreamDataCb: OnProxyData
    onCloseCb: OnProxyClose
    onErrorCb: OnProxyError

const
  DefaultMaxPending* = 1 * 1024 * 1024  ## 1 MiB per pair pending buffer cap

# ── Forward declarations ─────────────────────────────────────────────────────

proc listen*(server: ProxyServer, address: string, port: int)
proc close*(server: ProxyServer)

# ── Internal: teardown ───────────────────────────────────────────────────────

proc teardown(server: ProxyServer, clientFd: int) =
  let pair = server.pairs.getOrDefault(clientFd)
  if pair == nil:
    return
  server.pairs.del(clientFd)
  if pair.upstream != nil:
    # upstream may already be Closed / fd == -1, so try both fd and scan
    if pair.upstream.fd.int >= 0:
      server.byUpstream.del(pair.upstream.fd.int)
    else:
      var toDel = -1
      for k, v in server.byUpstream:
        if v == clientFd:
          toDel = k
          break
      if toDel >= 0:
        server.byUpstream.del(toDel)
    if pair.upstream.state != Closed:
      pair.upstream.close()
  if pair.client != nil and pair.client.state != Closed:
    pair.client.close()

proc teardownByUpstreamFd*(server: ProxyServer, upstreamFd: int): int =
  ## Find the clientFd for an upstream fd and tear that pair down. Returns
  ## clientFd or -1.
  result = server.byUpstream.getOrDefault(upstreamFd, -1)
  if result < 0:
    for fd, p in server.pairs:
      if p.upstream != nil and p.upstream.fd.int == upstreamFd:
        result = fd
        break
      # fd may be -1 after close, compare object identity
      if p.upstream != nil and cast[pointer](p.upstream) == cast[pointer](server.pairs.getOrDefault(fd).upstream):
        discard
  if result >= 0:
    let p = server.pairs.getOrDefault(result)
    if p != nil and server.onCloseCb != nil:
      server.onCloseCb(p, FromUpstream)
    server.teardown(result)

# ── Frontend factory ─────────────────────────────────────────────────────────

proc buildFrontend(server: ProxyServer): TcpServer =
  let s = server
  result = newTcpServer(s.loop,
    onAccept = proc(client: Connection) =
      if s.closed:
        client.close()
        return
      if not s.useUnix and (s.upstreamHost.len == 0 or s.upstreamPort == 0):
        if s.onErrorCb != nil:
          let pair = ProxyPair(id: s.nextId, client: client)
          inc s.nextId
          s.onErrorCb(pair, "proxy: no upstream configured; call setUpstream first")
        client.close()
        return
      let clientFd = client.fd.int
      let pair = ProxyPair(id: s.nextId, client: client, pending: @[])
      inc s.nextId
      s.pairs[clientFd] = pair
      if s.onConnectCb != nil:
        s.onConnectCb(pair)

      # upstream onData/onClose/onError need clientFd captured; use separate
      # closures per pair to avoid aliasing.
      let capturedClientFd = clientFd

      if s.useUnix:
        when not defined(windows):
          s.loop.connectUnix(s.upstreamUnixPath,
            onConnect = proc(upstream: Connection) =
              let p = s.pairs.getOrDefault(capturedClientFd)
              if p == nil or p.client.state == Closed:
                upstream.close()
                return
              p.upstream = upstream
              s.byUpstream[upstream.fd.int] = capturedClientFd
              if s.onUpstreamConnectCb != nil:
                s.onUpstreamConnectCb(p)
              if p.pending.len > 0:
                discard upstream.send(p.pending)
                p.pending.setLen(0)
            ,
            onData = proc(upstream: Connection, data: openArray[byte]) =
              let cfd = s.byUpstream.getOrDefault(upstream.fd.int, -1)
              var p: ProxyPair
              if cfd >= 0:
                p = s.pairs.getOrDefault(cfd)
              else:
                for fd, pp in s.pairs:
                  if pp.upstream == upstream:
                    p = pp
                    break
              if p == nil or p.client == nil or p.client.state == Closed:
                return
              if s.onDataCb != nil: s.onDataCb(p, FromUpstream, data)
              if s.onUpstreamDataCb != nil: s.onUpstreamDataCb(p, FromUpstream, data)
              discard p.client.send(data)
            ,
            onClose = proc(upstream: Connection) =
              if s.closed: return
              var cfd = s.byUpstream.getOrDefault(upstream.fd.int, -1)
              if cfd < 0:
                for fd, pp in s.pairs:
                  if pp.upstream == upstream:
                    cfd = fd
                    break
              if cfd >= 0:
                if s.onCloseCb != nil:
                  let p = s.pairs.getOrDefault(cfd)
                  if p != nil: s.onCloseCb(p, FromUpstream)
                s.teardown(cfd)
          )
        else:
          if s.onErrorCb != nil:
            let p = s.pairs.getOrDefault(capturedClientFd)
            if p != nil: s.onErrorCb(p, "connectUnix not supported on Windows")
          s.teardown(capturedClientFd)
      else:
        s.loop.connect(s.upstreamHost, s.upstreamPort,
          onConnect = proc(upstream: Connection) =
            let p = s.pairs.getOrDefault(capturedClientFd)
            if p == nil or p.client.state == Closed:
              upstream.close()
              return
            p.upstream = upstream
            s.byUpstream[upstream.fd.int] = capturedClientFd
            if s.onUpstreamConnectCb != nil:
              s.onUpstreamConnectCb(p)
            if p.pending.len > 0:
              discard upstream.send(p.pending)
              p.pending.setLen(0)
          ,
          onData = proc(upstream: Connection, data: openArray[byte]) =
            let cfd = s.byUpstream.getOrDefault(upstream.fd.int, -1)
            var p: ProxyPair
            if cfd >= 0:
              p = s.pairs.getOrDefault(cfd)
            else:
              for fd, pp in s.pairs:
                if pp.upstream == upstream:
                  p = pp
                  break
            if p == nil or p.client == nil or p.client.state == Closed:
              return
            if s.onDataCb != nil: s.onDataCb(p, FromUpstream, data)
            if s.onUpstreamDataCb != nil: s.onUpstreamDataCb(p, FromUpstream, data)
            discard p.client.send(data)
          ,
          onClose = proc(upstream: Connection) =
            if s.closed: return
            var cfd = s.byUpstream.getOrDefault(upstream.fd.int, -1)
            if cfd < 0:
              for fd, pp in s.pairs:
                if pp.upstream == upstream:
                  cfd = fd
                  break
            if cfd >= 0:
              if s.onCloseCb != nil:
                let p = s.pairs.getOrDefault(cfd)
                if p != nil: s.onCloseCb(p, FromUpstream)
              s.teardown(cfd)
          ,
          onError = proc(err: string) =
            let p = s.pairs.getOrDefault(capturedClientFd)
            if p != nil and s.onErrorCb != nil:
              s.onErrorCb(p, err)
            s.teardown(capturedClientFd)
        )
    ,
    onData = proc(client: Connection, data: openArray[byte]) =
      # find pair — client.fd may be -1 after close, so scan fallback
      var p = s.pairs.getOrDefault(client.fd.int)
      if p == nil:
        for pp in s.pairs.values:
          if pp.client == client:
            p = pp
            break
      if p == nil:
        return
      if s.onDataCb != nil: s.onDataCb(p, FromClient, data)
      if s.onClientDataCb != nil: s.onClientDataCb(p, FromClient, data)
      if p.upstream == nil:
        if p.pending.len + data.len > s.maxPending:
          if s.onErrorCb != nil:
            s.onErrorCb(p, "pending buffer overflow")
          # locate clientFd for teardown
          var cfd = -1
          for k, v in s.pairs:
            if v == p: cfd = k; break
          if cfd >= 0: s.teardown(cfd)
          return
        let old = p.pending.len
        p.pending.setLen(old + data.len)
        copyMem(addr p.pending[old], unsafeAddr data[0], data.len)
      else:
        discard p.upstream.send(data)
    ,
    onClose = proc(client: Connection) =
      if s.closed: return
      var cfd = -1
      if client.fd.int >= 0:
        cfd = client.fd.int
        if cfd notin s.pairs:
          cfd = -1
      if cfd < 0:
        for k, v in s.pairs:
          if v.client == client:
            cfd = k
            break
      if cfd >= 0:
        if s.onCloseCb != nil:
          let p = s.pairs.getOrDefault(cfd)
          if p != nil: s.onCloseCb(p, FromClient)
        s.teardown(cfd)
  )
  result.maxConnections = s.maxConnections

# ── Construction ─────────────────────────────────────────────────────────────

proc newProxyServer*(loop: Loop): ProxyServer =
  ## Create a proxy that uses `loop`. The loop is not owned; `close` will not
  ## close it, but `stop` will.
  ProxyServer(
    loop: loop,
    frontends: @[],
    pairs: initTable[int, ProxyPair](64),
    byUpstream: initTable[int, int](64),
    maxPending: DefaultMaxPending,
    maxConnections: 0,
    ownsLoop: false,
    closed: false,
  )

proc newProxyServer*(): ProxyServer =
  ## Create a proxy with its own event loop (like `newHttpServer()`).
  let loop = newLoop()
  ProxyServer(
    loop: loop,
    frontends: @[],
    pairs: initTable[int, ProxyPair](64),
    byUpstream: initTable[int, int](64),
    maxPending: DefaultMaxPending,
    maxConnections: 0,
    ownsLoop: true,
    closed: false,
  )

proc newProxyServer*(upstreamHost: string, upstreamPort: int,
                     loop: Loop = nil): ProxyServer =
  ## Convenience: create a proxy already pointed at `upstreamHost:upstreamPort`.
  let l = if loop != nil: loop else: newLoop()
  result = ProxyServer(
    loop: l,
    frontends: @[],
    upstreamHost: upstreamHost,
    upstreamPort: upstreamPort,
    pairs: initTable[int, ProxyPair](64),
    byUpstream: initTable[int, int](64),
    maxPending: DefaultMaxPending,
    maxConnections: 0,
    ownsLoop: loop == nil,
    closed: false,
  )

# ── Friendly callback setters (chainable) ────────────────────────────────────

proc onConnect*(server: ProxyServer, cb: OnProxyConnect): ProxyServer {.discardable.} =
  ## Called when a client is accepted, before the upstream connect.
  server.onConnectCb = cb
  server

proc onUpstreamConnect*(server: ProxyServer,
                        cb: OnProxyUpstreamConnect): ProxyServer {.discardable.} =
  ## Called when the upstream for a pair connects (`pair.upstream` is set).
  server.onUpstreamConnectCb = cb
  server

proc onData*(server: ProxyServer, cb: OnProxyData): ProxyServer {.discardable.} =
  ## Data notification for both directions. `dir` is `FromClient` or
  ## `FromUpstream`. Forwarding is automatic before this fires.
  server.onDataCb = cb
  server

proc onClientData*(server: ProxyServer, cb: OnProxyData): ProxyServer {.discardable.} =
  ## Sugar for `onData` filtered to `FromClient`.
  server.onClientDataCb = cb
  server

proc onUpstreamData*(server: ProxyServer, cb: OnProxyData): ProxyServer {.discardable.} =
  ## Sugar for `onData` filtered to `FromUpstream`.
  server.onUpstreamDataCb = cb
  server

proc onClose*(server: ProxyServer, cb: OnProxyClose): ProxyServer {.discardable.} =
  ## Either side of a pair closed; `dir` says which side.
  server.onCloseCb = cb
  server

proc onError*(server: ProxyServer, cb: OnProxyError): ProxyServer {.discardable.} =
  ## Upstream connect / DNS error, or pending overflow.
  server.onErrorCb = cb
  server

# ── Upstream config ──────────────────────────────────────────────────────────

proc setUpstream*(server: ProxyServer, host: string, port: int) =
  ## Set (or change) the static upstream. Takes effect for new pairs.
  server.upstreamHost = host
  server.upstreamPort = port
  server.useUnix = false
  server.upstreamUnixPath = ""

when not defined(windows):
  proc setUpstreamUnix*(server: ProxyServer, path: string) =
    ## Use a Unix domain socket as upstream.
    server.upstreamUnixPath = path
    server.useUnix = true
    server.upstreamHost = ""
    server.upstreamPort = 0

proc setMaxPending*(server: ProxyServer, bytes: int) =
  ## Per-pair pending buffer cap before the client connects (default 1 MiB).
  server.maxPending = bytes

proc setMaxConnections*(server: ProxyServer, n: int) =
  ## Cap concurrent frontend connections (0 = unlimited). Applied to new
  ## frontends; existing frontends keep their current limit.
  server.maxConnections = n
  for ts in server.frontends:
    ts.maxConnections = n

# ── Loop / lifecycle ─────────────────────────────────────────────────────────

proc getLoop*(server: ProxyServer): Loop {.inline.} =
  ## The event loop owned (or borrowed) by this proxy.
  ## Prefer `run()` — it hides the loop entirely. `getLoop` is for advanced
  ## cases where you need to share the loop with another server.
  server.loop

proc run*(server: ProxyServer) {.inline.} =
  ## Run the owned event loop. Blocks until `stop()` or `close()` is called
  ## from a callback / signal. This is the high-level counterpart to
  ## `HttpServer`'s `loop.run()` — the loop itself is never exposed.
  server.loop.run()

proc listen*(server: ProxyServer, address: string, port: int) =
  ## Bind an additional frontend listen socket. Additive — call repeatedly
  ## before `loop.run()` to front multiple ports with the same upstream.
  let ts = server.buildFrontend()
  ts.listen(address, port)
  server.frontends.add(ts)

when not defined(windows):
  proc listenUnix*(server: ProxyServer, path: string, mode: int = 0o660) =
    ## Listen on a Unix domain socket.
    let ts = server.buildFrontend()
    ts.listenUnix(path, mode)
    server.frontends.add(ts)

proc close*(server: ProxyServer) =
  ## Tear down all pairs and frontend listeners. Keeps the loop alive so the
  ## caller can reuse it; use `stop` to also close the loop.
  if server.closed: return
  server.closed = true
  let pairsCopy = toSeq(server.pairs.values)
  server.pairs.clear()
  server.byUpstream.clear()
  for p in pairsCopy:
    if p.upstream != nil and p.upstream.state != Closed:
      p.upstream.close()
    if p.client != nil and p.client.state != Closed:
      p.client.close()
  for ts in server.frontends:
    ts.close()
  server.frontends.setLen(0)
  server.closed = false

proc stop*(server: ProxyServer) =
  ## `close` + close the owned loop (if any). No-op for a borrowed loop.
  server.close()
  if server.ownsLoop and server.loop != nil:
    server.loop.close()

proc start*(server: ProxyServer, port: Port) =
  ## Shorthand: `listen("0.0.0.0", port)` then `loop.run()` (blocking).
  server.listen("0.0.0.0", port.int)
  server.loop.run()

proc start*(server: ProxyServer, ports: varargs[Port]) =
  ## Multi-port: `proxy.start(Port(9020), Port(9021))` on `0.0.0.0`.
  if ports.len == 0:
    raise newException(ValueError, "start: at least one Port is required")
  for p in ports:
    server.listen("0.0.0.0", p.int)
  server.loop.run()

proc start*(server: ProxyServer, address: string, ports: varargs[Port]) =
  ## Multi-port on explicit `address`: `proxy.start("127.0.0.1", Port(9020))`.
  if ports.len == 0:
    raise newException(ValueError, "start: at least one Port is required")
  for p in ports:
    server.listen(address, p.int)
  server.loop.run()
