## tests/test_client_timeouts.nim — H1 client timeout policy (Phase 1B, B4).
## Connect / read-inactivity / total deadlines.

import std/httpcore except HttpMethod
import std/[unittest]
import ../src/powpow

# Silent server: accepts and holds the connection without responding.
proc silentServer(loop: Loop, port: int): TcpServer =
  result = newTcpServer(loop,
    onAccept = proc(conn: Connection) = discard,
    onData = proc(conn: Connection, data: openArray[byte]) = discard,
    onClose = proc(conn: Connection) = discard,
  )
  result.listen("127.0.0.1", port)

test "timeout_read_fires_on_silent_server":
  let client = newHttpClient(readTimeoutMs = 300)
  let server = silentServer(client.getLoop(), 19900)

  var msg = ""
  try:
    discard client.get("http://127.0.0.1:19900/")
  except HttpError as e:
    msg = e.msg
  check msg == "read timed out"

  server.close()
  client.close()

test "timeout_total_still_fires":
  let client = newHttpClient(timeoutMs = 300)
  let server = silentServer(client.getLoop(), 19901)

  var msg = ""
  try:
    discard client.get("http://127.0.0.1:19901/")
  except HttpError as e:
    msg = e.msg
  check msg == "request timed out"

  server.close()
  client.close()

test "timeout_no_spurious_fire_on_fast_server":
  let client = newHttpClient(timeoutMs = 5000, connectTimeoutMs = 2000,
                             readTimeoutMs = 2000)
  let server = newHttpServer(client.getLoop())
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http200).send("fast")
  server.listen("127.0.0.1", 19902)

  let r = client.get("http://127.0.0.1:19902/")
  check r.getStatusCode() == Http200
  check r.getBodyString() == "fast"
  # Second request reuses the pooled connection under the same policy.
  let r2 = client.get("http://127.0.0.1:19902/")
  check r2.getBodyString() == "fast"

  server.close()
  client.close()

test "timeout_read_resets_on_progress":
  # First byte arrives, then the server stalls: the deadline runs from the
  # last byte, not from connect.
  let client = newHttpClient(readTimeoutMs = 400)
  let server = newTcpServer(client.getLoop(),
    onAccept = proc(conn: Connection) = discard,
    onData = proc(conn: Connection, data: openArray[byte]) =
      {.gcsafe.}:
        discard conn.send("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
    ,
    onClose = proc(conn: Connection) = discard,
  )
  server.listen("127.0.0.1", 19903)

  var msg = ""
  try:
    discard client.get("http://127.0.0.1:19903/")
  except HttpError as e:
    msg = e.msg
  check msg == "read timed out"

  server.close()
  client.close()
