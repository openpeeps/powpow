## examples/proxyserver.nim — High-level TCP reverse proxy demo.
##
## Demonstrates `ProxyServer`, the high-level wrapper around `TcpServer` +
## `Loop` + pair state. Compare with `examples/tcp_proxy.nim` (low-level):
## there the proxy is hand-rolled with `newTcpServer` + `loop.connect` +
## `Table[int,ProxyPair]` + `pending` + `teardown`. Here `ProxyServer`
## owns the event loop and the frontend `TcpServer`(s) internally — you only
## configure the upstream and the friendly `onXxx` callbacks.
##
## Bytes flow both ways. Client bytes arriving before the upstream connects are
## buffered and flushed once it connects. Closing either side tears down the pair.
##
## Run:
##   # 1. Start a backend to proxy to (any TCP server on 127.0.0.1:9001):
##   #    nim c -r examples/tcp_proxy.nim   # provides echo on :9021, or use `nc -l 9001`
##   # 2. Run this proxy:
##   nim c -r examples/proxyserver.nim
##   # or with clue:
##   clue build --out:/tmp/proxyserver examples/proxyserver.nim && /tmp/proxyserver
##
## Test:
##   nc 127.0.0.1 9020        # type a line; the backend echoes it back

import ../src/powpow/proto/proxyserver

# Proxy owns its Loop (like HttpServer) — no manual `newLoop` / `newTcpServer`
# needed. Just pick the upstream and wire the callbacks.
let proxy = newProxyServer("127.0.0.1", 9001)

# ── Friendly callbacks — all chainable, all `gcsafe` ─────────────────────────

proxy
  .onConnect(proc(pair: ProxyPair) {.gcsafe.} =
    echo "⚡ client fd=", pair.client.fd.int, " accepted (id=", pair.id, ")")
  .onUpstreamConnect(proc(pair: ProxyPair) {.gcsafe.} =
    echo "⚡ proxied client fd=", pair.client.fd.int,
         " -> upstream fd=", pair.upstream.fd.int)
  .onData(proc(pair: ProxyPair, dir: ProxyDir,
               data: openArray[byte]) {.gcsafe.} =
    let label = if dir == FromClient: "C->U" else: "U->C"
    echo "  ", label, " ", data.len, " bytes (id=", pair.id, ")")
  # Direction-specific sugar (filters `onData` internally):
  # .onClientData(proc(pair: ProxyPair, dir: ProxyDir, data: openArray[byte]) {.gcsafe.} =
  #   echo "  C->U ", data.len, " bytes")
  # .onUpstreamData(proc(pair: ProxyPair, dir: ProxyDir, data: openArray[byte]) {.gcsafe.} =
  #   echo "  U->C ", data.len, " bytes")
  .onClose(proc(pair: ProxyPair, dir: ProxyDir) {.gcsafe.} =
    echo "⚡ closed from ", dir, " id=", pair.id)
  .onError(proc(pair: ProxyPair, err: string) {.gcsafe.} =
    echo "⚡ error (id=", pair.id, "): ", err)

# ── Upstream & listen — all high-level ───────────────────────────────────────

# Change upstream at any time (takes effect for new pairs):
# proxy.setUpstream("127.0.0.1", 9002)
# proxy.setUpstreamUnix("/tmp/backend.sock")   # Unix socket upstream (POSIX)
# proxy.setMaxPending(2 * 1024 * 1024)          # per-pair buffer cap (default 1 MiB)
# proxy.setMaxConnections(1000)                 # frontend connection cap

# Single port — blocks and runs the owned Loop internally:
# proxy.start(Port(9020))

# Multi-port — same handler/upstream on several frontends:
# proxy.start(Port(9020), Port(9021))

proxy.listen("0.0.0.0", 9020)
# proxy.listen("0.0.0.0", 9021)   # add more frontends as needed
echo "⚡ proxy listening on 0.0.0.0:9020 -> 127.0.0.1:9001"
echo "  Connect with:  nc 127.0.0.1 9020"
echo "  Press Ctrl+C to stop"
proxy.run()

# `run()` owns the loop — no `getLoop()` needed. For multi-port use:
#   proxy.start(Port(9020), Port(9021))  # listen + run in one call
# For sharing the loop with another server, `getLoop()` is still available.
