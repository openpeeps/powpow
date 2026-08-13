## Security tests for the HTTP client: malformed / malicious servers and URLs
## must fail the request — never crash, hang, or allocate unbounded memory.

import std/[asyncdispatch, httpcore, strutils, unittest]
import ../src/powpow

proc rawServer(loop: Loop, port: int,
               respond: proc(conn: Connection, data: openArray[byte]) {.closure.}): TcpServer =
  result = newTcpServer(loop,
    onAccept = proc(conn: Connection) = discard,
    onData = respond,
    onClose = proc(conn: Connection) = discard,
  )
  result.listen("127.0.0.1", port)

proc expectFailure(client: HttpClient, port: int, path = "/") =
  ## A request expected to fail must error with a specific message, not time out.
  var msg = ""
  try:
    discard client.get("http://127.0.0.1:" & $port & path)
  except HttpError as e:
    msg = e.msg
  check msg.len > 0
  check "timed out" notin msg

# ── URL parsing ─────────────────────────────────────────────────────────────

test "sec_malformed_url":
  let client = newHttpClient(timeoutMs = 500)
  for url in ["notaurl", "http://", "ftp://host/", "://host/",
              "http://host:portx/", "http:///path"]:
    expect HttpError:
      discard client.get(url)
  # CR/LF in the host or path must be rejected outright (request injection).
  expect HttpError:
    discard client.get("http://evil.com\r\nX-Evil: yes/")
  expect HttpError:
    discard client.get("http://host/\r\nGET / HTTP/1.1\r\n")
  client.close()

test "sec_header_injection":
  let client = newHttpClient(timeoutMs = 500)
  expect HttpError:
    discard client.get("http://127.0.0.1:19979/", [("X-Test", "a\r\nInjected: yes")])
  expect HttpError:
    discard client.get("http://127.0.0.1:19979/", [("X-Test\nFoo", "b")])
  client.close()

# ── Malformed / hostile responses ───────────────────────────────────────────

test "sec_bad_status_line":
  let client = newHttpClient(timeoutMs = 2000)
  let server = rawServer(client.getLoop(), 19960, proc(conn: Connection, data: openArray[byte]) =
    discard conn.send("GARBAGE\r\n\r\n")
    conn.shutdown())
  expectFailure(client, 19960)
  server.close()
  client.close()

test "sec_oversized_headers":
  let client = newHttpClient(timeoutMs = 2000)
  let server = rawServer(client.getLoop(), 19961, proc(conn: Connection, data: openArray[byte]) =
    discard conn.send("HTTP/1.1 200 OK\r\nX-Pad: " & repeat('a', 9000) & "\r\n\r\n")
    conn.shutdown())
  expectFailure(client, 19961)
  server.close()
  client.close()

test "sec_invalid_status_code":
  let client = newHttpClient(timeoutMs = 2000)
  let server = rawServer(client.getLoop(), 19962, proc(conn: Connection, data: openArray[byte]) =
    discard conn.send("HTTP/1.1 abc OK\r\n\r\n")
    conn.shutdown())
  expectFailure(client, 19962)
  server.close()
  client.close()

test "sec_http2_rejected":
  let client = newHttpClient(timeoutMs = 2000)
  let server = rawServer(client.getLoop(), 19963, proc(conn: Connection, data: openArray[byte]) =
    discard conn.send("HTTP/2.0 200 OK\r\n\r\n")
    conn.shutdown())
  expectFailure(client, 19963)
  server.close()
  client.close()

test "sec_te_and_content_length":
  let client = newHttpClient(timeoutMs = 2000)
  let server = rawServer(client.getLoop(), 19964, proc(conn: Connection, data: openArray[byte]) =
    discard conn.send("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n" &
                      "Content-Length: 5\r\n\r\n0\r\n\r\n")
    conn.shutdown())
  expectFailure(client, 19964)
  server.close()
  client.close()

test "sec_malformed_chunked":
  let client = newHttpClient(timeoutMs = 2000)
  let server = rawServer(client.getLoop(), 19965, proc(conn: Connection, data: openArray[byte]) =
    discard conn.send("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\n\r\n")
    conn.shutdown())
  expectFailure(client, 19965)
  server.close()
  client.close()

test "sec_truncated_body":
  let client = newHttpClient(timeoutMs = 2000)
  let server = rawServer(client.getLoop(), 19966, proc(conn: Connection, data: openArray[byte]) =
    discard conn.send("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
    conn.shutdown())
  expectFailure(client, 19966)
  server.close()
  client.close()

test "sec_premature_close_during_headers":
  let client = newHttpClient(timeoutMs = 2000)
  let server = rawServer(client.getLoop(), 19967, proc(conn: Connection, data: openArray[byte]) =
    discard conn.send("HTTP/1.1 200 OK\r\nContent-")
    conn.shutdown())
  expectFailure(client, 19967)
  server.close()
  client.close()

test "sec_oversized_declared_body":
  let client = newHttpClient(timeoutMs = 2000, maxBodySize = 1024)
  let server = rawServer(client.getLoop(), 19968, proc(conn: Connection, data: openArray[byte]) =
    discard conn.send("HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n")
    conn.shutdown())
  expectFailure(client, 19968)
  server.close()
  client.close()

test "sec_chunked_exceeds_cap":
  let client = newHttpClient(timeoutMs = 2000, maxBodySize = 1024)
  let server = rawServer(client.getLoop(), 19971, proc(conn: Connection, data: openArray[byte]) =
    discard conn.send("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" &
                      "800\r\n" & repeat('b', 0x800) & "\r\n0\r\n\r\n")
    conn.shutdown())
  expectFailure(client, 19971)
  server.close()
  client.close()

test "sec_async_malformed_response":
  let client = newAsyncHttpClient(timeoutMs = 2000)
  let server = rawServer(client.loop, 19969, proc(conn: Connection, data: openArray[byte]) =
    discard conn.send("GARBAGE\r\n\r\n")
    conn.shutdown())
  var errMsg = ""
  try:
    discard waitFor(client.get("http://127.0.0.1:19969/"))
  except HttpError as e:
    errMsg = e.msg
  check errMsg.len > 0
  check "timed out" notin errMsg
  server.close()
  client.close()
