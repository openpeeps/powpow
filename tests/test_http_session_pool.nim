## tests/test_http_session_pool.nim — Session pooling + lazy tracking (HTTP/1.1).
##
## Covers the `perf/http1-perf` pooling work:
##   - `ConnHttp` objects are recycled across connections (no per-conn alloc)
##     with full state reset (no cross-connection leakage).
##   - `Connection: close` sessions live and die in the unhashed pending list
##     and never touch `connRoots`.
##   - keep-alive sessions are promoted to `connRoots` on first completion.
##   - pre-first-response stalls are still bounded by `readTimeoutMs` (slowloris).

import ../src/powpow
import std/httpcore except HttpMethod
import std/[strutils, tables, unittest]

const TestPort = 20171

test "test_close_conn_never_touches_roots_and_recycles_session":
  var bodies: seq[string] = @[]
  let loop = newLoop()
  let server = newHttpServer(loop, populate = false)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http200).send(req.getPath())
  server.listen("127.0.0.1", TestPort)

  var connsDone = 0
  proc fetch(path: string) =
    loop.connect("127.0.0.1", TestPort,
      onConnect = proc(conn: Connection) =
        discard conn.send("GET " & path & " HTTP/1.1\r\nHost: x\r\n" &
                          "Connection: close\r\n\r\n")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        var s = newString(data.len)
        copyMem(addr s[0], unsafeAddr data[0], data.len)
        bodies.add(s)
        conn.close()
      ,
      onClose = proc(conn: Connection) =
        inc connsDone
        if connsDone == 1:
          fetch("/second")
        else:
          server.close()
          loop.stop()
    )

  discard loop.addTimer(5000) do (id: int):
    server.close()
    loop.stop()

  fetch("/first")
  loop.run()
  loop.close()

  doAssert bodies.len == 2, "both responses must arrive, got " & $bodies.len
  doAssert bodies[0].endsWith("/first"), "first body intact, got: " & bodies[0]
  doAssert bodies[1].endsWith("/second"), "second body intact (no session leak), got: " & bodies[1]
  doAssert server.connRoots.len == 0, "close-conn must never enter connRoots"
  doAssert server.pendingConns.len == 0, "pending list must drain"
  doAssert server.connHttpPool.len > 0, "sessions must be recycled to the pool"

test "test_keepalive_promotes_to_roots":
  let loop = newLoop()
  let server = newHttpServer(loop, populate = false)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http200).send("ok")
  server.listen("127.0.0.1", TestPort + 1)

  var gotBody = false
  discard loop.addTimer(50) do (id: int):
    loop.connect("127.0.0.1", TestPort + 1,
      onConnect = proc(conn: Connection) =
        discard conn.send("GET /a HTTP/1.1\r\nHost: x\r\n\r\n")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        gotBody = true
        # Keep the connection open: server must have promoted the session.
        doAssert server.pendingConns.len == 0, "promoted out of pending"
        doAssert server.connRoots.len == 1, "keep-alive session tracked in roots"
        conn.close()
      ,
      onClose = proc(conn: Connection) =
        server.close()
        loop.stop()
    )

  discard loop.addTimer(5000) do (id: int):
    server.close()
    loop.stop()

  loop.run()
  loop.close()
  doAssert gotBody, "keep-alive response must arrive"
  doAssert server.connRoots.len == 0, "roots must drain after close"
  doAssert server.pendingConns.len == 0, "pending must drain after close"

test "test_pending_slowloris_bounded_by_read_timeout":
  let loop = newLoop()
  let server = newHttpServer(loop, populate = false)
  server.readTimeoutMs = 150
  server.timeoutSweepMs = 25
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http200).send("unreachable")
  server.listen("127.0.0.1", TestPort + 2)

  var clientClosed = false
  discard loop.addTimer(50) do (id: int):
    loop.connect("127.0.0.1", TestPort + 2,
      onConnect = proc(conn: Connection) =
        # Partial headers, then stall forever (slowloris drip).
        discard conn.send("GET /slow HTTP/1.1\r\nHost: x\r\n")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        conn.close()
      ,
      onClose = proc(conn: Connection) =
        clientClosed = true
        server.close()
        loop.stop()
    )

  discard loop.addTimer(5000) do (id: int):
    server.close()
    loop.stop()

  loop.run()
  loop.close()
  doAssert clientClosed, "stalled pre-first-response conn must be reaped by the sweep"
  doAssert server.pendingConns.len == 0, "reaped session must leave pending"
  doAssert server.connRoots.len == 0, "reaped session must not be in roots"
