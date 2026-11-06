## audit/proxy_limits.nim
##
## ProxyServer abuse pins: missing/refused upstreams fail closed, half-close
## tears down the pair, maxConnections caps frontends, and the proxy keeps
## serving afterwards (no leaked pairs, no dead frontend).

import powpow/proto/proxyserver
import std/[unittest, strutils]

proc pollUntil(loop: Loop; pred: proc(): bool; maxPolls: int): int =
  result = 0
  while not pred() and result < maxPolls:
    loop.poll(1)
    inc result

proc startEcho(loop: Loop; port: int): TcpServer =
  result = newTcpServer(loop,
    onData = proc(conn: Connection; data: openArray[byte]) =
      discard conn.send(data)
  )
  result.listen("127.0.0.1", port)

suite "proxy abuse limits":

  test "no upstream configured closes client and fires onError":
    let proxy = newProxyServer()
    let loop = proxy.getLoop()
    var errMsg = ""
    proxy.onError(proc(p: ProxyPair; err: string) {.gcsafe.} =
      {.cast(gcsafe).}:
        errMsg = err)
    proxy.listen("127.0.0.1", 39731)
    var closed = false
    var clientErr = ""
    loop.connect("127.0.0.1", 39731,
      onConnect = proc(c: Connection) = discard,
      onData = proc(c: Connection; data: openArray[byte]) = discard,
      onClose = proc(c: Connection) = closed = true,
      onError = proc(e: string) = clientErr = e)
    discard pollUntil(loop, proc(): bool = errMsg.len > 0 and
      (closed or clientErr.len > 0), 20_000)
    check errMsg.contains("no upstream")
    check closed or clientErr.len > 0
    proxy.stop()

  test "transparent echo round trip both directions":
    let proxy = newProxyServer()
    let loop = proxy.getLoop()
    let echoSrv = startEcho(loop, 39732)
    proxy.setUpstream("127.0.0.1", 39732)
    proxy.listen("127.0.0.1", 39733)
    var got = ""
    var done = false
    loop.connect("127.0.0.1", 39733,
      onConnect = proc(c: Connection) = discard c.send("hello-proxy"),
      onData = proc(c: Connection; data: openArray[byte]) =
        for b in data: got.add(char(b))
        if got.len >= 11: done = true,
      onClose = proc(c: Connection) = discard,
      onError = proc(e: string) = discard)
    discard pollUntil(loop, proc(): bool = done, 20_000)
    check got == "hello-proxy"
    echoSrv.close()
    proxy.stop()

  test "refused upstream fails closed and proxy stays usable":
    let proxy = newProxyServer()
    let loop = proxy.getLoop()
    proxy.setUpstream("127.0.0.1", 39734)
    proxy.listen("127.0.0.1", 39735)
    var errors = 0
    proxy.onError(proc(p: ProxyPair; err: string) {.gcsafe.} =
      {.cast(gcsafe).}:
        inc errors)
    for i in 0 ..< 2:
      var released = false
      loop.connect("127.0.0.1", 39735,
        onConnect = proc(c: Connection) = discard,
        onData = proc(c: Connection; data: openArray[byte]) = discard,
        onClose = proc(c: Connection) = released = true,
        onError = proc(e: string) = released = true)
      discard pollUntil(loop, proc(): bool = released, 20_000)
      check released
    check errors == 2
    # Proxy still works once the upstream comes up (no leaked pairs).
    let echoSrv = startEcho(loop, 39734)
    var got = ""
    var done = false
    loop.connect("127.0.0.1", 39735,
      onConnect = proc(c: Connection) = discard c.send("back"),
      onData = proc(c: Connection; data: openArray[byte]) =
        for b in data: got.add(char(b))
        if got.len >= 4: done = true,
      onClose = proc(c: Connection) = discard,
      onError = proc(e: string) = discard)
    discard pollUntil(loop, proc(): bool = done, 20_000)
    check got == "back"
    echoSrv.close()
    proxy.stop()

  test "client close tears down pair with FromClient":
    let proxy = newProxyServer()
    let loop = proxy.getLoop()
    let echoSrv = startEcho(loop, 39736)
    proxy.setUpstream("127.0.0.1", 39736)
    proxy.listen("127.0.0.1", 39737)
    var closeDir = FromUpstream
    var closeSeen = false
    proxy.onClose(proc(p: ProxyPair; dir: ProxyDir) {.gcsafe.} =
      {.cast(gcsafe).}:
        closeDir = dir
        closeSeen = true)
    var echoed = false
    var client: Connection = nil
    loop.connect("127.0.0.1", 39737,
      onConnect = proc(c: Connection) =
        client = c
        discard c.send("hi"),
      onData = proc(c: Connection; data: openArray[byte]) =
        echoed = true
        c.close(),
      onClose = proc(c: Connection) = discard,
      onError = proc(e: string) = discard)
    discard pollUntil(loop, proc(): bool = closeSeen and echoed, 20_000)
    check echoed
    check closeSeen
    check closeDir == FromClient
    # A fresh client still round-trips (pair was cleaned up).
    var got = ""
    var done = false
    loop.connect("127.0.0.1", 39737,
      onConnect = proc(c: Connection) = discard c.send("again"),
      onData = proc(c: Connection; data: openArray[byte]) =
        for b in data: got.add(char(b))
        if got.len >= 5: done = true,
      onClose = proc(c: Connection) = discard,
      onError = proc(e: string) = discard)
    discard pollUntil(loop, proc(): bool = done, 20_000)
    check got == "again"
    echoSrv.close()
    proxy.stop()

  test "maxConnections caps the frontend, first client unaffected":
    let proxy = newProxyServer()
    let loop = proxy.getLoop()
    let echoSrv = startEcho(loop, 39738)
    proxy.setUpstream("127.0.0.1", 39738)
    proxy.setMaxConnections(1)
    proxy.listen("127.0.0.1", 39739)
    var firstEcho = ""
    var firstDone = false
    loop.connect("127.0.0.1", 39739,
      onConnect = proc(c: Connection) = discard c.send("first"),
      onData = proc(c: Connection; data: openArray[byte]) =
        for b in data: firstEcho.add(char(b))
        if firstEcho.len >= 5: firstDone = true,
      onClose = proc(c: Connection) = discard,
      onError = proc(e: string) = discard)
    discard pollUntil(loop, proc(): bool = firstDone, 20_000)
    check firstEcho == "first"
    var secondClosed = false
    loop.connect("127.0.0.1", 39739,
      onConnect = proc(c: Connection) = discard,
      onData = proc(c: Connection; data: openArray[byte]) = discard,
      onClose = proc(c: Connection) = secondClosed = true,
      onError = proc(e: string) = discard)
    discard pollUntil(loop, proc(): bool = secondClosed, 20_000)
    check secondClosed
    echoSrv.close()
    proxy.stop()
