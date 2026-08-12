## Proves the HttpServer ws pool RETAINS pooled WsConnections.
##
## A released ws is returned to the pool with its conn detached. If the pool
## held only a raw `pointer` (as it did), ARC would free the ws as soon as the
## last real reference dropped, and the next upgrade would pop a dangling
## pointer (use-after-free -> nimDecRefIsLast SIGSEGV). The pool must hold a
## real `ref RootObj`.

import std/unittest
import ../src/powpow

test "ws_pool_retains_object":
  let loop = newLoop()
  let server = newHttpServer(loop)
  let conn = newConnection(SocketHandle(-1), loop, nil, acquireBuf(loop), DefaultBufSize)

  var ws = newWsConnection(conn, 65536)
  ws.onMessage = proc(w: WsConnection, k: WsFrameKind, d: openArray[byte]) = discard

  # Simulate the release path: detach the connection and clear callbacks, then
  # return the ws to the pool.
  ws.conn = nil
  ws.onMessage = nil
  server.wsPoolAdd(cast[ref RootObj](ws))
  ws = nil   # the pool is now the only holder

  # Churn same-shaped allocations: if the pool leaked the ws (raw pointer),
  # ARC freed it and these (identical WsConnection type) reallocate its block,
  # so popping it later reads reused memory.
  var junk: seq[WsConnection]
  for i in 0 ..< 3000:
    let c = newConnection(SocketHandle(-1), loop, nil, acquireBuf(loop), DefaultBufSize)
    junk.add(newWsConnection(c, 1024))

  let back = server.wsPoolPop()
  check back != nil
  let ws2 = cast[WsConnection](back)
  # The pool must have retained the ORIGINAL object: it is still the detached
  # ws with maxFrameSize intact (a reused block would show the junk conn).
  check ws2.conn == nil
  check ws2.maxFrameSize == 65536

  loop.close()
