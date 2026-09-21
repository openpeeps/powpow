## HTTP client tests: sync (HttpClient) and async (AsyncHttpClient),
## including Unix domain sockets, keep-alive reuse, streaming, chunked and
## close-delimited bodies.
##
## Sync tests host the server on the client's own loop (via `getLoop`) so the
## client's blocking `poll` drives both sides on a single thread.

import std/httpcore except HttpMethod
import std/[asyncdispatch, os, sequtils, strutils, unittest]
import ../src/powpow

# ── Sync tests (server lives on the sync client's loop) ─────────────────────

test "sync_http_get":
  var seen: seq[string]
  let client = newHttpClient()
  let server = newHttpServer(client.getLoop())
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      seen.add(req.getPath())
    res.status(Http200).header("Content-Type", "text/plain").send("ok")
  server.listen("127.0.0.1", 19970)

  let res = client.get("http://127.0.0.1:19970/hello")
  check res.getStatusCode() == Http200
  check res.getBodyString() == "ok"
  check res.getHeaders()["Content-Type"] == "text/plain"
  check seen == @["/hello"]

  server.close()
  client.close()

test "sync_http_post":
  let client = newHttpClient()
  let server = newHttpServer(client.getLoop())
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      res.status(Http200).send(req.getBodyString())
  server.listen("127.0.0.1", 19971)

  let res = client.post("http://127.0.0.1:19971/echo", "hello body")
  check res.getStatusCode() == Http200
  check res.getBodyString() == "hello body"

  server.close()
  client.close()

test "sync_http_head_no_hang":
  let client = newHttpClient()
  let server = newHttpServer(client.getLoop())
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http200).send("ok")
  server.listen("127.0.0.1", 19972)

  let res = client.head("http://127.0.0.1:19972/")
  # The point is that HEAD does not wait for a Content-Length body that never
  # arrives. (The test server ignores the method and sends a body anyway.)
  check res.getStatusCode() == Http200

  server.close()
  client.close()

test "sync_keepalive_reuses_connection":
  var rounds = 0
  var conns: seq[int]
  let client = newHttpClient()
  let server = newHttpServer(client.getLoop())
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      inc rounds
      conns.add(res.getConn().fd.int)
    res.status(Http200).send("ok")
  server.listen("127.0.0.1", 19973)

  let a = client.get("http://127.0.0.1:19973/a")
  let b = client.get("http://127.0.0.1:19973/b")
  check a.getBodyString() == "ok"
  check b.getBodyString() == "ok"
  check rounds == 2
  check conns.deduplicate().len == 1

  server.close()
  client.close()

test "sync_http_chunked":
  let client = newHttpClient()
  let server = newTcpServer(client.getLoop(),
    onAccept = proc(conn: Connection) = discard,
    onData = proc(conn: Connection, data: openArray[byte]) =
      discard conn.send("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n" &
                        "Connection: close\r\n\r\n" &
                        "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    ,
    onClose = proc(conn: Connection) = discard,
  )
  server.listen("127.0.0.1", 19974)

  let res = client.get("http://127.0.0.1:19974/")
  check res.getStatusCode() == Http200
  check res.getBodyString() == "hello world"

  server.close()
  client.close()

test "sync_http_close_delimited":
  let client = newHttpClient()
  let server = newTcpServer(client.getLoop(),
    onAccept = proc(conn: Connection) = discard,
    onData = proc(conn: Connection, data: openArray[byte]) =
      discard conn.send("HTTP/1.1 200 OK\r\n\r\nclose-delimited-body")
      conn.shutdown()
    ,
    onClose = proc(conn: Connection) = discard,
  )
  server.listen("127.0.0.1", 19975)

  let res = client.get("http://127.0.0.1:19975/")
  check res.getStatusCode() == Http200
  check res.getBodyString() == "close-delimited-body"

  server.close()
  client.close()

test "sync_http_timeout":
  let client = newHttpClient(timeoutMs = 100)
  let server = newTcpServer(client.getLoop(),
    onAccept = proc(conn: Connection) = discard,
    onData = proc(conn: Connection, data: openArray[byte]) = discard,
    onClose = proc(conn: Connection) = discard,
  )
  server.listen("127.0.0.1", 19976)

  expect HttpError:
    discard client.get("http://127.0.0.1:19976/")

  server.close()
  client.close()

test "sync_http_connect_refused":
  let client = newHttpClient(timeoutMs = 500)
  expect HttpError:
    discard client.get("http://127.0.0.1:19979/")
  client.close()

when not defined(windows):
  test "sync_http_uds":
    let sockPath = getTempDir() & "powpow_httpclient_test.sock"
    let client = newHttpClient()
    let server = newTcpServer(client.getLoop(),
      onAccept = proc(conn: Connection) = discard,
      onData = proc(conn: Connection, data: openArray[byte]) =
        discard conn.send("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
      ,
      onClose = proc(conn: Connection) = discard,
    )
    server.listenUnix(sockPath)

    let res = client.get("http://localhost/", [], unixSocket = sockPath)
    check res.getStatusCode() == Http200
    check res.getBodyString() == "hello"

    server.close()
    client.close()
    removeFile(sockPath)

# ── Async tests (await-able; server lives on the async client's loop) ───────

test "async_http_get":
  let client = newAsyncHttpClient()
  let server = newHttpServer(client.loop)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http200).send("async-ok")
  server.listen("127.0.0.1", 19977)

  let res = waitFor(client.get("http://127.0.0.1:19977/"))
  check res.getStatusCode() == Http200
  check res.getBodyString() == "async-ok"

  server.close()
  client.close()

test "async_http_post":
  let client = newAsyncHttpClient()
  let server = newHttpServer(client.loop)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http200).send(req.getBodyString())
  server.listen("127.0.0.1", 19977)

  let res = waitFor(client.post("http://127.0.0.1:19977/echo", "async body"))
  check res.getBodyString() == "async body"

  server.close()
  client.close()

test "async_http_large_body":
  let client = newAsyncHttpClient()
  let server = newTcpServer(client.loop,
    onAccept = proc(conn: Connection) = discard,
    onData = proc(conn: Connection, data: openArray[byte]) =
      discard conn.send("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n" &
                        "Connection: close\r\n\r\n")
      var chunk = newSeq[byte](100000)
      for i in 0 ..< 100000: chunk[i] = byte('a')
      discard conn.send(chunk)
    ,
    onClose = proc(conn: Connection) = discard,
  )
  server.listen("127.0.0.1", 19978)

  let res = waitFor(client.get("http://127.0.0.1:19978/"))
  check res.getBody().len == 100000

  server.close()
  client.close()

test "async_http_close_delimited":
  let client = newAsyncHttpClient()
  let server = newTcpServer(client.loop,
    onAccept = proc(conn: Connection) = discard,
    onData = proc(conn: Connection, data: openArray[byte]) =
      discard conn.send("HTTP/1.1 200 OK\r\n\r\nxyz")
      conn.shutdown()
    ,
    onClose = proc(conn: Connection) = discard,
  )
  server.listen("127.0.0.1", 19980)

  let res = waitFor(client.get("http://127.0.0.1:19980/"))
  check res.getBodyString() == "xyz"

  server.close()
  client.close()

test "async_http_concurrent_guard":
  let client = newAsyncHttpClient()
  let server = newHttpServer(client.loop)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http200).send("ok")
  server.listen("127.0.0.1", 19977)

  let fut1 = client.get("http://127.0.0.1:19977/a")
  let fut2 = client.get("http://127.0.0.1:19977/b")
  check fut2.failed
  check fut2.error.msg.contains("concurrent")

  discard waitFor(fut1)
  server.close()
  client.close()

# ── Connection pool tests ───────────────────────────────────────────────────

# Raw TCP server that answers every request with a keep-alive 200 and counts
# accepted connections — fd numbers are recycled by the OS, so server-side
# accept counts are the only honest way to observe connection reuse.
proc keepAliveEchoServer(loop: Loop, port: int, accepts: ptr int): TcpServer =
  newTcpServer(loop,
    onAccept = proc(conn: Connection) =
      inc accepts[]
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      discard conn.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n" &
                        "\r\nok")
    ,
    onClose = proc(conn: Connection) = discard,
  )

test "pool_reuses_same_origin":
  var accepts = 0
  let client = newHttpClient()
  let server = keepAliveEchoServer(client.getLoop(), 19980, addr accepts)
  server.listen("127.0.0.1", 19980)

  discard client.get("http://127.0.0.1:19980/a")
  check client.idleConnections() == 1
  discard client.get("http://127.0.0.1:19980/b")
  check accepts == 1
  check client.idleConnections() == 1

  server.close()
  client.close()
  check client.idleConnections() == 0

test "pool_keeps_origins_apart":
  # The pre-pool code reused the single idle slot across hosts — a request
  # meant for B could be sent over A's socket.
  var acceptsA = 0
  var acceptsB = 0
  let client = newHttpClient()
  let loop = client.getLoop()
  let srvA = keepAliveEchoServer(loop, 19981, addr acceptsA)
  srvA.listen("127.0.0.1", 19981)
  let srvB = keepAliveEchoServer(loop, 19982, addr acceptsB)
  srvB.listen("127.0.0.1", 19982)

  discard client.get("http://127.0.0.1:19981/a")
  check client.idleConnections() == 1
  discard client.get("http://127.0.0.1:19982/b")
  check client.idleConnections() == 2
  discard client.get("http://127.0.0.1:19981/c")
  discard client.get("http://127.0.0.1:19982/d")

  check acceptsA == 1
  check acceptsB == 1

  srvA.close(); srvB.close()
  client.close()

test "pool_max_total_evicts_oldest":
  var acceptsA = 0
  var acceptsC = 0
  let client = newHttpClient(maxIdlePerHost = 4, maxIdleTotal = 1,
                             idleTimeoutMs = 60_000)
  let loop = client.getLoop()
  let srvA = keepAliveEchoServer(loop, 19983, addr acceptsA)
  srvA.listen("127.0.0.1", 19983)
  let srvC = keepAliveEchoServer(loop, 19984, addr acceptsC)
  srvC.listen("127.0.0.1", 19984)

  discard client.get("http://127.0.0.1:19983/a")   # pools connA (total=1)
  discard client.get("http://127.0.0.1:19984/c")   # pushes connC -> evicts connA
  check client.idleConnections() == 1

  discard client.get("http://127.0.0.1:19983/a2")  # connA was evicted -> fresh
  check acceptsA == 2
  check acceptsC == 1

  srvA.close(); srvC.close()
  client.close()

test "pool_idle_timeout_lazily_expires":
  var accepts = 0
  let client = newHttpClient(idleTimeoutMs = 50)
  let server = keepAliveEchoServer(client.getLoop(), 19985, addr accepts)
  server.listen("127.0.0.1", 19985)

  discard client.get("http://127.0.0.1:19985/a")
  sleep(120)  # exceed idleTimeoutMs; expiry is checked on next pop
  discard client.get("http://127.0.0.1:19985/b")
  check accepts == 2

  server.close()
  client.close()

test "pool_connection_close_not_pooled":
  var rounds = 0
  let client = newHttpClient()
  let server = newTcpServer(client.getLoop(),
    onAccept = proc(conn: Connection) = discard,
    onData = proc(conn: Connection, data: openArray[byte]) =
      inc rounds
      discard conn.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n" &
                        "Connection: close\r\n\r\nok")
    ,
    onClose = proc(conn: Connection) = discard,
  )
  server.listen("127.0.0.1", 19986)

  discard client.get("http://127.0.0.1:19986/a")
  check client.idleConnections() == 0

  server.close()
  client.close()

test "pool_stale_conn_retry":
  # Server responds with keep-alive semantics but the pooled connection is
  # killed while idle. The next request pops the dead socket and must
  # succeed transparently via one fresh retry (accepted == 2).
  var accepted = 0
  var closed = 0
  var lastConn: Connection = nil
  let client = newHttpClient(idleTimeoutMs = 60_000)
  let loop = client.getLoop()
  let server = newTcpServer(loop,
    onAccept = proc(conn: Connection) =
      inc accepted
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      lastConn = conn
      discard conn.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n" &
                        "Connection: keep-alive\r\n\r\nok")
    ,
    onClose = proc(conn: Connection) = discard,
  )
  server.listen("127.0.0.1", 19987)

  let r1 = client.get("http://127.0.0.1:19987/first")
  check r1.getBodyString() == "ok"
  check accepted == 1

  # Doom the pooled connection while it is idle. The timer is driven
  # explicitly here so it can never slip into the next request and kill an
  # ACTIVE connection mid-flight (that race is timing-dependent and flakes
  # across kernels/load). Afterwards the RST propagates while the loop is
  # not driven, so the pop deterministically reuses a dead socket.
  discard loop.addTimer(20) do (id: int):
    if lastConn != nil:
      lastConn.close()
      inc closed
  let doomDeadline = monoMs() + 2000
  while closed == 0 and monoMs() < doomDeadline:
    loop.poll(1)
  check closed == 1

  sleep(300)  # let the RST land so the pop observes a dead socket
  let r2 = client.get("http://127.0.0.1:19987/second")
  check r2.getBodyString() == "ok" # stale pooled connection must retry silently
  check accepted == 2

  server.close()
  client.close()

test "pool_rst_conn_retry":
  # powpow closes server-side sockets with linger-0, so a server-side close
  # lands as RST rather than FIN. Kill the pooled connection outright, wait
  # for the RST to arrive, then request: whether the dead socket surfaces as
  # a send error or a recv error, the request must succeed transparently via
  # one fresh retry (accepted == 2 proves the retry happened).
  var accepted = 0
  var lastConn: Connection = nil
  let client = newHttpClient(idleTimeoutMs = 60_000)
  let loop = client.getLoop()
  let server = newTcpServer(loop,
    onAccept = proc(conn: Connection) =
      inc accepted
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      lastConn = conn
      discard conn.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n" &
                        "Connection: keep-alive\r\n\r\nok")
    ,
    onClose = proc(conn: Connection) = discard,
  )
  server.listen("127.0.0.1", 19995)

  let r1 = client.get("http://127.0.0.1:19995/first")
  check r1.getBodyString() == "ok"
  check accepted == 1

  lastConn.close()  # RST; the pooled connection is dead from here on
  sleep(300)        # let the RST land so the pop observes a dead socket

  let r2 = client.get("http://127.0.0.1:19995/second")
  check r2.getBodyString() == "ok" # RST pooled connection must retry silently
  check accepted == 2

  server.close()
  client.close()

test "async_pool_reuses_connection":
  let client = newAsyncHttpClient()
  var conns: seq[int]
  let server = newHttpServer(client.loop)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      conns.add(res.getConn().fd.int)
    res.status(Http200).send("ok")
  server.listen("127.0.0.1", 19988)

  let a = waitFor client.get("http://127.0.0.1:19988/a")
  check a.getBodyString() == "ok"
  check client.idleConnections() == 1
  let b = waitFor client.get("http://127.0.0.1:19988/b")
  check b.getBodyString() == "ok"
  check conns.deduplicate().len == 1

  server.close()
  client.close()

# ── Expect: 100-continue ────────────────────────────────────────────────────

test "server_sends_100_continue_before_body":
  # Raw-socket client announces Expect: 100-continue, waits for the interim
  # response, then ships the body. The final 200 must follow.
  let serverLoop = newLoop()
  let server = newHttpServer(serverLoop)
  var bodies: seq[string]
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      bodies.add(req.getBodyString())
    res.status(Http200).send("done")
  server.listen("127.0.0.1", 19990)

  var resp = ""
  var bodySent = false
  serverLoop.connect("127.0.0.1", 19990,
    onConnect = proc(conn: Connection) =
      discard conn.send("POST /upload HTTP/1.1\r\n" &
                        "Host: localhost\r\n" &
                        "Content-Length: 5\r\n" &
                        "Expect: 100-continue\r\n" &
                        "\r\n")
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      resp.add cast[string](@data)
      if not bodySent and "100 Continue" in resp:
        bodySent = true
        discard conn.send("hello")
    ,
    onClose = proc(conn: Connection) = discard,
  )
  discard serverLoop.addTimer(3000) do (id: int):
    serverLoop.stop()
  serverLoop.run()

  check resp.contains("HTTP/1.1 100 Continue")
  check resp.contains("HTTP/1.1 200")
  check bodies == @["hello"]

  server.close()
  serverLoop.close()

test "client_consumes_interim_100_continue":
  # Server sends an unprompted 100 Continue followed by the real response;
  # the client must deliver only the final one.
  let client = newHttpClient()
  let loop = client.getLoop()
  let server = newTcpServer(loop,
    onAccept = proc(conn: Connection) = discard
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      discard conn.send("HTTP/1.1 100 Continue\r\n\r\n" &
                        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nfine")
    ,
    onClose = proc(conn: Connection) = discard,
  )
  server.listen("127.0.0.1", 19991)

  let res = client.get("http://127.0.0.1:19991/")
  check res.getStatusCode() == Http200
  check res.getBodyString() == "fine"

  server.close()
  client.close()

test "client_expect_100_continue_roundtrip":
  # Client sends Expect: 100-continue via headers; powpow server emits the
  # interim response; client skips it and surfaces the final response.
  var gotBody = ""
  let client = newHttpClient()
  let loop = client.getLoop()
  let server = newHttpServer(loop)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      gotBody = req.getBodyString()
    res.status(Http201).send("created")
  server.listen("127.0.0.1", 19992)

  let res = client.post("http://127.0.0.1:19992/thing", "payload",
                        headers = [("Expect", "100-continue")])
  check res.getStatusCode() == Http201
  check res.getBodyString() == "created"
  check gotBody == "payload"

  server.close()
  client.close()
