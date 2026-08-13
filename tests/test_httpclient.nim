## HTTP client tests: sync (HttpClient) and async (AsyncHttpClient),
## including Unix domain sockets, keep-alive reuse, streaming, chunked and
## close-delimited bodies.
##
## Sync tests host the server on the client's own loop (via `getLoop`) so the
## client's blocking `poll` drives both sides on a single thread.

import std/[asyncdispatch, httpcore, os, sequtils, strutils, unittest]
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
