## tests/test_server_mgmt.nim — access logging (A5) + graceful drain (A6).

import std/httpcore except HttpMethod
import std/[strutils, unittest]
import ../src/powpow

# ── A5: access log ─────────────────────────────────────────────────────────────

test "accesslog_basic":
  var entries: seq[AccessLogEntry]
  let client = newHttpClient()
  let server = newHttpServer(client.getLoop())
  server.onAccessLog = proc(e: AccessLogEntry) {.closure, gcsafe.} =
    {.gcsafe.}:
      entries.add(e)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    if req.getPath() == "/missing":
      res.sendError(Http404, "nope")
    else:
      res.status(Http200).header("Content-Type", "text/plain").send("ok")
  server.listen("127.0.0.1", 19874)

  discard client.get("http://127.0.0.1:19874/a")
  discard client.get("http://127.0.0.1:19874/missing")
  check entries.len == 2
  check entries[0].httpMethod == HttpGet
  check entries[0].path == "/a"
  check entries[0].statusCode == 200
  check entries[0].clientIp == "127.0.0.1"
  check entries[0].durationMs >= 0
  check entries[0].streaming == false
  check entries[1].path == "/missing"
  check entries[1].statusCode == 404
  check entries[1].clientIp == "127.0.0.1"

  server.close()
  client.close()

test "accesslog_bad_request":
  var entries: seq[AccessLogEntry]
  let loop = newLoop()
  let server = newHttpServer(loop)
  server.onAccessLog = proc(e: AccessLogEntry) {.closure, gcsafe.} =
    {.gcsafe.}:
      entries.add(e)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http200).send("ok")
  server.listen("127.0.0.1", 19875)

  var closed = false
  loop.connect("127.0.0.1", 19875,
    onConnect = proc(conn: Connection) =
      discard conn.send("GET / HTTP/1.1\r\n Bad-Header: x\r\n\r\n"),
    onData = proc(conn: Connection, data: openArray[byte]) = discard,
    onClose = proc(conn: Connection) =
      {.gcsafe.}:
        closed = true
        server.close()
        loop.stop()
  )
  discard loop.addTimer(5000) do (id: int):
    server.close()
    loop.stop()
  loop.run()

  check closed
  check entries.len == 1
  check entries[0].statusCode == 400
  check entries[0].clientIp == "127.0.0.1"

test "accesslog_streaming_flag":
  # The handler returns with the stream still open: the dispatch-time entry
  # reports streaming=true (time-to-first-byte semantics).
  let loop = newLoop()
  let server = newHttpServer(loop)
  var entries: seq[AccessLogEntry]
  server.onAccessLog = proc(e: AccessLogEntry) {.closure, gcsafe.} =
    {.gcsafe.}:
      entries.add(e)
  var stream: SseStream
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      stream = res.startSse()
  server.listen("127.0.0.1", 19876)

  var received = ""
  loop.connect("127.0.0.1", 19876,
    onConnect = proc(conn: Connection) =
      discard conn.send("GET /events HTTP/1.1\r\nHost: x\r\n\r\n"),
    onData = proc(conn: Connection, data: openArray[byte]) =
      {.gcsafe.}:
        for b in data:
          received.add(char(b))
        if "data: x" in received:
          conn.close()
          server.close()
          loop.stop()
  )
  discard loop.addTimer(100) do (id: int):
    if stream != nil:
      stream.sendEvent("x")
      stream.close()
  discard loop.addTimer(5000) do (id: int):
    server.close()
    loop.stop()
  loop.run()

  check entries.len == 1
  check entries[0].statusCode == 200
  check entries[0].streaming == true
  check "data: x" in received

# ── A6: drain ──────────────────────────────────────────────────────────────────

test "drain_empty_fires_inline":
  let loop = newLoop()
  let server = newHttpServer(loop)
  server.listen("127.0.0.1", 19877)
  var drained = false
  server.drain(1000, proc() {.closure, gcsafe.} =
    {.gcsafe.}:
      drained = true
  )
  check drained
  check server.tcpServers.len == 1
  check server.tcpServers[0].fd.int == -1
  server.close()
  loop.close()

test "drain_closes_idle_and_listener":
  let loop = newLoop()
  let server = newHttpServer(loop)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http200).send("ok")
  server.listen("127.0.0.1", 19878)

  var drained = false
  var clientGone = false
  var listenFd = 0
  var drainArmed = false
  loop.connect("127.0.0.1", 19878,
    onConnect = proc(conn: Connection) =
      discard conn.send("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"),
    onData = proc(conn: Connection, data: openArray[byte]) =
      {.gcsafe.}:
        if not drainArmed:
          drainArmed = true
          discard loop.addTimer(50) do (id: int):
            # onDrained must NOT stop the loop: teardown FINs still need
            # polls to flush. The client observes the FIN and stops below.
            server.drain(2000, proc() {.closure, gcsafe.} =
              {.gcsafe.}:
                listenFd = server.tcpServers[0].fd.int
                drained = true
                server.close()
            )
    ,
    onClose = proc(conn: Connection) =
      {.gcsafe.}:
        clientGone = true
        loop.stop()
  )
  discard loop.addTimer(8000) do (id: int):
    server.close()
    loop.stop()
  loop.run()

  check drained
  check clientGone
  check listenFd == -1

test "drain_waits_for_open_stream":
  let loop = newLoop()
  let server = newHttpServer(loop)
  var stream: SseStream
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      stream = res.startSse()
  server.listen("127.0.0.1", 19879)

  var received = ""
  var drained = false
  var lateConnect = false
  var listenFd = 0
  loop.connect("127.0.0.1", 19879,
    onConnect = proc(conn: Connection) =
      discard conn.send("GET /events HTTP/1.1\r\nHost: x\r\n\r\n"),
    onData = proc(conn: Connection, data: openArray[byte]) =
      {.gcsafe.}:
        for b in data:
          received.add(char(b))
        if received.endsWith("0\r\n\r\n"):
          # Full stream arrived; the FIN follows. Stop from here so the
          # teardown flush (event + terminator) is never truncated.
          conn.close()
          server.close()
          loop.stop()
  )
  # Drain while the stream is open: the listener dies but the stream lives.
  # onDrained must NOT stop the loop (see above); the client stops it.
  discard loop.addTimer(100) do (id: int):
    server.drain(2000, proc() {.closure, gcsafe.} =
      {.gcsafe.}:
        listenFd = server.tcpServers[0].fd.int
        drained = true
        server.close()
    )
  # A post-drain connect must never establish.
  discard loop.addTimer(150) do (id: int):
    loop.connect("127.0.0.1", 19879,
      onConnect = proc(conn: Connection) =
        {.gcsafe.}:
          lateConnect = true
      ,
      onData = proc(conn: Connection, data: openArray[byte]) = discard,
      onError = proc(err: string) = discard
    )
  # Finish the stream after the drain: the event still arrives, then drain fires.
  discard loop.addTimer(250) do (id: int):
    if stream != nil:
      stream.sendEvent("late")
      stream.close()
  discard loop.addTimer(8000) do (id: int):
    server.close()
    loop.stop()
  loop.run()

  check listenFd == -1
  check lateConnect == false
  check "data: late" in received
  check received.endsWith("0\r\n\r\n")
  check drained
