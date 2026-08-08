## examples/tcp_proxy.nim — TCP reverse proxy / load balancer.
##
## Demonstrates the low-level TCP layer's bidirectional forwarding: clients
## connecting to :9020 are proxied to a backend echo server on :9021. Bytes flow
## both ways, and closing either side tears down the pair. Client bytes that
## arrive before the upstream connection is established are buffered and flushed
## once it connects.
##
## Run:
##   nim c -r examples/tcp_proxy.nim
##
## Test:
##   nc 127.0.0.1 9020        # type a line; the backend echoes it back
##
## A tiny echo backend is started automatically on :9021.

import ../src/powpow
import std/[tables, strutils]

const ProxyPort = 9020
const BackendPort = 9021

let loop = newLoop()

# ── Backend echo server on :9021 ──────────────────────────────────────────────

var backend = newTcpServer(loop,
  onAccept = proc(conn: Connection) = discard,
  onData = proc(conn: Connection, data: openArray[byte]) =
    discard conn.send("backend echo: " & $cast[string](@data))
  ,
)
backend.listen("0.0.0.0", BackendPort)
echo "⚡ backend echo server listening on 0.0.0.0:" & $BackendPort

# ── Proxy on :9020 — forward between clients and the backend ────────────────

type ProxyPair = ref object
  client:   Connection
  upstream: Connection
  pending:  string            # client bytes buffered until upstream connects

var pairs = initTable[int, ProxyPair]()     # keyed by client fd
var byUpstream = initTable[int, int]()      # upstream fd -> client fd

proc teardown(clientFd: int) =
  ## Close and forget a proxied pair given the client's fd.
  let pair = pairs.getOrDefault(clientFd)
  pairs.del(clientFd)
  if pair == nil:
    return
  if pair.upstream != nil:
    byUpstream.del(pair.upstream.fd.int)
  if pair.client != nil and pair.client.state != Closed:
    pair.client.close()
  if pair.upstream != nil and pair.upstream.state != Closed:
    pair.upstream.close()

var proxy = newTcpServer(loop,
  onAccept = proc(clientConn: Connection) =
    let pair = ProxyPair(client: clientConn)
    pairs[clientConn.fd.int] = pair
    loop.connect("127.0.0.1", BackendPort,
      onConnect = proc(upstream: Connection) =
        let pair = pairs.getOrDefault(clientConn.fd.int)
        if pair == nil or pair.client.state == Closed:
          # The client vanished while we were connecting — drop the upstream.
          upstream.close()
          return
        pair.upstream = upstream
        byUpstream[upstream.fd.int] = clientConn.fd.int
        echo "⚡ proxied client fd=", clientConn.fd.int,
             " -> backend fd=", upstream.fd.int
        if pair.pending.len > 0:
          discard upstream.send(pair.pending)
          pair.pending = ""
      ,
      onData = proc(upstream: Connection, data: openArray[byte]) =
        let clientFd = byUpstream.getOrDefault(upstream.fd.int)
        if clientFd >= 0:
          let pair = pairs.getOrDefault(clientFd)
          if pair != nil and pair.client != nil and pair.client.state != Closed:
            discard pair.client.send(data)
      ,
      onClose = proc(upstream: Connection) =
        # Find the pair by scanning for this upstream (pairs are keyed by client).
        var clientFd = -1
        for fd, p in pairs:
          if p.upstream == upstream:
            clientFd = fd
            break
        if clientFd >= 0:
          echo "⚡ backend closed fd=", upstream.fd.int, " — tearing down pair"
          teardown(clientFd)
      ,
    )
  ,
  onData = proc(clientConn: Connection, data: openArray[byte]) =
    let pair = pairs.getOrDefault(clientConn.fd.int)
    if pair == nil:
      return
    if pair.upstream == nil:
      pair.pending.add(cast[string](@data))   # buffer until upstream connects
    else:
      discard pair.upstream.send(data)
  ,
  onClose = proc(clientConn: Connection) =
    echo "⚡ client closed fd=", clientConn.fd.int, " — tearing down pair"
    teardown(clientConn.fd.int)
  ,
)
proxy.listen("0.0.0.0", ProxyPort)
echo "⚡ proxy listening on 0.0.0.0:" & $ProxyPort
echo "  Connect with:  nc 127.0.0.1 " & $ProxyPort
echo "  Press Ctrl+C to stop"
loop.run()
