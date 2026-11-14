## tests/test_sse.nim — Server-Sent Events: framing helpers, incremental
## client parser, and live chunked-stream round trips (sync + timer-driven).

import std/httpcore except HttpMethod
import std/[strutils, unittest]
import ../src/powpow

# ── Unit: formatSseEvent ─────────────────────────────────────────────────────

test "sse_format_basic":
  check formatSseEvent("hello") == "data: hello\n\n"

test "sse_format_named":
  check formatSseEvent("hi", event = "greet") == "event: greet\ndata: hi\n\n"

test "sse_format_full":
  check formatSseEvent("hi", event = "greet", id = "7", retry = 3000) ==
    "id: 7\nevent: greet\ndata: hi\nretry: 3000\n\n"

test "sse_format_multiline":
  check formatSseEvent("a\nb\r\nc") == "data: a\ndata: b\ndata: c\n\n"

test "sse_format_empty_data":
  # Empty payload still yields a dispatchable data line, not a bare blank.
  check formatSseEvent("") == "data: \n\n"

test "sse_format_sanitizes_fields":
  check formatSseEvent("x", event = "a\nb", id = "1\r\n2") ==
    "id: 12\nevent: ab\ndata: x\n\n"

# ── Unit: formatSseComment ───────────────────────────────────────────────────

test "sse_comment":
  check formatSseComment("ping") == ": ping\n\n"
  check formatSseComment() == ":\n\n"

# ── Unit: SseParser ──────────────────────────────────────────────────────────

test "sse_parser_single_feed":
  let p = newSseParser()
  let evs = p.feed("event: hi\ndata: hello\n\n")
  check evs.len == 1
  check evs[0].event == "hi"
  check evs[0].data == "hello"

test "sse_parser_split_feed":
  let p = newSseParser()
  check p.feed("event: hi\nda").len == 0
  let evs = p.feed("ta: hello\n\n")
  check evs.len == 1
  check evs[0].event == "hi"
  check evs[0].data == "hello"

test "sse_parser_defaults_and_comments":
  let p = newSseParser()
  let evs = p.feed(": heartbeat\n\ndata: x\n\n")
  check evs.len == 1
  check evs[0].event == "message"
  check evs[0].data == "x"

test "sse_parser_id_persists":
  let p = newSseParser()
  let a = p.feed("id: 42\ndata: one\n\n")
  check a.len == 1
  check a[0].id == "42"
  let b = p.feed("data: two\n\n")
  check b.len == 1
  check b[0].id == "42"

test "sse_parser_retry_and_crlf":
  let p = newSseParser()
  let evs = p.feed("retry: 1500\r\ndata: x\r\n\r\n")
  check evs.len == 1
  check evs[0].retry == 1500

test "sse_parser_multiline_data":
  let p = newSseParser()
  let evs = p.feed("data: a\ndata: b\n\n")
  check evs.len == 1
  check evs[0].data == "a\nb"

test "sse_parser_roundtrip_with_formatter":
  let p = newSseParser()
  let wire = formatSseEvent("l1\nl2", event = "e", id = "9", retry = 100)
  let evs = p.feed(wire)
  check evs.len == 1
  check evs[0].event == "e"
  check evs[0].data == "l1\nl2"
  check evs[0].id == "9"
  check evs[0].retry == 100

# ── Integration: sync handler streams then closes ────────────────────────────

test "sse_sync_roundtrip":
  let client = newHttpClient()
  let server = newHttpServer(client.getLoop())
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    let s = res.startSse()
    s.sendEvent("tick 1", event = "tick")
    s.sendEvent("tick 2", event = "tick", id = "2")
    s.close()
  server.listen("127.0.0.1", 19871)

  let res = client.get("http://127.0.0.1:19871/events")
  check res.getStatusCode() == Http200
  check res.getHeaders()["Content-Type"] == "text/event-stream"
  let parser = newSseParser()
  let evs = parser.feed(res.getBodyString())
  check evs.len == 2
  check evs[0].event == "tick"
  check evs[0].data == "tick 1"
  check evs[1].id == "2"
  check evs[1].data == "tick 2"

  server.close()
  client.close()

# ── Integration: events pushed from timers after handler returns ─────────────

test "sse_async_timer_events":
  let loop = newLoop()
  let server = newHttpServer(loop)
  var stream: SseStream
  var gotEvents = 0
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      stream = res.startSse()
      discard loop.addTimer(30) do (id: int):
        stream.sendEvent("tick 1", event = "tick")
      discard loop.addTimer(60) do (id: int):
        stream.sendEvent("tick 2", event = "tick", id = "2")
        stream.close()
  server.listen("127.0.0.1", 19872)

  var received = ""
  loop.connect("127.0.0.1", 19872,
    onConnect = proc(conn: Connection) =
      discard conn.send("GET /events HTTP/1.1\r\nHost: x\r\n\r\n"),
    onData = proc(conn: Connection, data: openArray[byte]) =
      {.gcsafe.}:
        for b in data:
          received.add(char(b))
        if received.endsWith("0\r\n\r\n"):
          conn.close()
          server.close()
          loop.stop()
  )
  discard loop.addTimer(5000) do (id: int):
    server.close()
    loop.stop()
  loop.run()

  check "HTTP/1.1 200" in received
  check "text/event-stream" in received
  check "Transfer-Encoding: chunked" in received
  check "event: tick" in received
  check "data: tick 1" in received
  check "data: tick 2" in received
  check received.endsWith("0\r\n\r\n")
  # Chunk-size framing: payload bytes wrapped in hex-length lines.
  check "\r\nevent: tick\n" in received

# ── Integration: trailers after the zero chunk ───────────────────────────────

test "sse_trailers":
  let loop = newLoop()
  let server = newHttpServer(loop)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    let s = res.startSse()
    s.sendEvent("done")
    s.close([("X-Checksum", "abc")])
  server.listen("127.0.0.1", 19873)

  var received = ""
  loop.connect("127.0.0.1", 19873,
    onConnect = proc(conn: Connection) =
      discard conn.send("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
    onData = proc(conn: Connection, data: openArray[byte]) =
      {.gcsafe.}:
        for b in data:
          received.add(char(b))
        if received.endsWith("\r\n\r\n"):
          conn.close()
          server.close()
          loop.stop()
  )
  discard loop.addTimer(5000) do (id: int):
    server.close()
    loop.stop()
  loop.run()

  check received.endsWith("0\r\nX-Checksum: abc\r\n\r\n")
