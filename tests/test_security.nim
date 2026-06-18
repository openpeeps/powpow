## tests/test_security.nim — Security tests for powpow.
##
## Covers: body size limits, overflow protection, DoS resistance,
##         connection limits, WebSocket frame limits, path traversal.
## All tests are deterministic — no timing-dependent assertions.
## Parser-level tests use zero-copy access patterns.

import ../src/powpow
import std/[unittest, strutils, httpcore]

# ══════════════════════════════════════════════════════════════════════
# Section 1: HTTP Parser Security
# ══════════════════════════════════════════════════════════════════════

test "test_max_body_size_rejects_large_content_length":
  let body = repeat('X', 200)
  let raw = "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 200\r\n\r\n" & body
  let parser = newHttpParser()
  parser.maxBodySize = 100
  parser.feed(raw)
  assert parser.isError(), "should error when CL exceeds maxBodySize"
  assert parser.error() == Http413

test "test_max_body_size_accepts_small_content_length":
  let body = repeat('X', 50)
  let raw = "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 50\r\n\r\n" & body
  let parser = newHttpParser()
  parser.maxBodySize = 100
  parser.feed(raw)
  assert parser.isComplete(), "should accept body within limit"
  let req = parser.getRequest()
  assert req.getBody().len == 50

test "test_max_body_size_rejects_chunked_overflow":
  let raw = "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n" &
            "32\r\n" & repeat('X', 50) & "\r\n" &
            "32\r\n" & repeat('X', 50) & "\r\n" &
            "0\r\n\r\n"
  let parser = newHttpParser()
  parser.maxBodySize = 75
  parser.feed(raw)
  assert parser.isError(), "should error when chunked body exceeds maxBodySize"
  assert parser.error() == Http413

test "test_max_body_size_chunked_at_limit":
  let raw = "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n" &
            "32\r\n" & repeat('X', 50) & "\r\n" &
            "0\r\n\r\n"
  let parser = newHttpParser()
  parser.maxBodySize = 50
  parser.feed(raw)
  assert parser.isComplete(), "should accept chunked body at limit"

test "test_content_length_overflow_handled_safely":
  let raw = "POST /overflow HTTP/1.1\r\nHost: localhost\r\nContent-Length: 99999999999999999999\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  assert parser.isError()
  assert parser.error() == Http413

test "test_max_body_size_zero_is_unlimited":
  let body = repeat('X', 50000)
  let raw = "POST /large HTTP/1.1\r\nHost: localhost\r\nContent-Length: 50000\r\n\r\n" & body
  let parser = newHttpParser()
  assert parser.maxBodySize == 0, "default maxBodySize should be 0 (unlimited)"
  parser.feed(raw)
  assert parser.isComplete(), "should accept large body when unlimited"
  let req = parser.getRequest()
  assert req.getBody().len == 50000

test "test_max_headers_exceeded":
  var raw = "GET / HTTP/1.1\r\nHost: localhost\r\n"
  for i in 0 ..< 101:
    raw.add("X-Header-" & $i & ": value" & $i & "\r\n")
  raw.add("\r\n")
  let parser = newHttpParser()
  parser.feed(raw)
  assert parser.isError()
  assert parser.error() == Http431

test "test_max_header_size_exceeded":
  # Header section without closing \r\n\r\n exceeding MaxHeaderSize (8192)
  let bigVal = repeat('A', 8200)
  let raw = "GET / HTTP/1.1\r\nHost: localhost\r\nX-Big: " & bigVal
  let parser = newHttpParser()
  parser.feed(raw)
  assert parser.isError()
  assert parser.error() == Http431

test "test_max_request_line_exceeded":
  let bigPath = "/" & repeat("A", 9000)
  let raw = "GET " & bigPath & " HTTP/1.1\r\nHost: localhost\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  assert parser.isError()
  assert parser.error() == Http414

test "test_chunk_size_overflow_rejected":
  let raw = "POST /overflow HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n" &
            "FFFFFFFFFFFFFFFF\r\n" &
            "X".repeat(1) & "\r\n" &
            "0\r\n\r\n"
  let parser = newHttpParser()
  parser.maxBodySize = 100
  parser.feed(raw)
  assert parser.isError(), "chunk hex overflow should be rejected"
  assert parser.error() == Http400

test "test_duplicate_content_length_different":
  let raw = "POST /dup HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello"
  let parser = newHttpParser()
  parser.feed(raw)
  assert parser.isError(), "duplicate CL with different values should be rejected"
  assert parser.error() == Http400

test "test_duplicate_content_length_same":
  let raw = "POST /dup HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"
  let parser = newHttpParser()
  parser.feed(raw)
  assert parser.isComplete(), "duplicate CL with same value should be accepted"

test "test_negative_content_length_rejected":
  let raw = "GET /neg HTTP/1.1\r\nHost: localhost\r\nContent-Length: -5\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  assert parser.isError(), "negative CL should be rejected"
  assert parser.error() == Http400

test "test_malformed_content_length_rejected":
  let raw = "GET /mal HTTP/1.1\r\nHost: localhost\r\nContent-Length: abc\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  assert parser.isError(), "malformed CL should be rejected"
  assert parser.error() == Http400

# ══════════════════════════════════════════════════════════════════════
# Section 2: HTTP Server Security
# ══════════════════════════════════════════════════════════════════════

test "test_no_auto_multipart_streaming":
  var handlerRan = false
  var streamerWasNil = false
  var multipartWorked = false
  let loop = newLoop()

  let server = newHttpServer(loop)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      handlerRan = true
      streamerWasNil = req.streamer == nil
      let mp = req.getMultipart()
      if mp != nil:
        multipartWorked = true
        mp.cleanup()
      res.status(Http200).send("OK")

  server.listen("127.0.0.1", 20091)

  let boundary = "----TestBoundary"
  let body = "------TestBoundary\r\n" &
             "Content-Disposition: form-data; name=\"field\"\r\n\r\n" &
             "value\r\n" &
             "------TestBoundary--\r\n"
  let request = "POST /form HTTP/1.1\r\nHost: localhost\r\n" &
                "Content-Type: multipart/form-data; boundary=----TestBoundary\r\n" &
                "Content-Length: " & $body.len & "\r\n\r\n" & body

  discard loop.addTimer(50) do (id: int):
    loop.connect("127.0.0.1", 20091,
      onConnect = proc(conn: Connection) =
        discard conn.send(request)
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        conn.close()
      ,
      onClose = proc(conn: Connection) =
        server.close()
        loop.stop()
    )

  discard loop.addTimer(3000) do (id: int):
    server.close()
    loop.stop()

  loop.run()
  loop.close()
  assert handlerRan, "handler should have been called"
  assert streamerWasNil, "streamer should be nil until getMultipart() is called"
  assert multipartWorked, "getMultipart() should work when called explicitly"

test "test_no_server_header_in_response":
  var responseData: seq[byte] = @[]
  let loop = newLoop()

  let server = newHttpServer(loop)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      res.status(Http200).header("Content-Type", "text/plain").send("ok")

  server.listen("127.0.0.1", 20092)

  discard loop.addTimer(50) do (id: int):
    loop.connect("127.0.0.1", 20092,
      onConnect = proc(conn: Connection) =
        discard conn.send("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        responseData.add(@data)
        conn.close()
      ,
      onClose = proc(conn: Connection) =
        server.close()
        loop.stop()
    )

  discard loop.addTimer(3000) do (id: int):
    server.close()
    loop.stop()

  loop.run()
  loop.close()
  let response = cast[string](responseData)
  assert "Server:" notin response, "response should not contain Server header"

proc testServeStaticRejects(port: int, path: string): string =
  var responseData: seq[byte] = @[]
  var clientConn: Connection = nil
  let loop = newLoop()

  let server = newHttpServer(loop)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      if not serveStatic(res, req, "/static", "/tmp"):
        res.sendError(Http404, "Not Found")

  server.listen("127.0.0.1", port)

  discard loop.addTimer(50) do (id: int):
    loop.connect("127.0.0.1", port,
      onConnect = proc(conn: Connection) =
        clientConn = conn
        discard conn.send("GET " & path & " HTTP/1.1\r\nHost: localhost\r\n\r\n")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        responseData.add(@data)
      ,
    )

  discard loop.addTimer(3000) do (id: int):
    if clientConn != nil: clientConn.close()
    server.close()
    loop.stop()

  # Poll until we have response data or timeout
  var polls = 0
  while responseData.len == 0 and polls < 50000:
    loop.poll(0)
    inc polls
  if responseData.len == 0:
    result = ""
  else:
    result = cast[string](responseData)
  if clientConn != nil: clientConn.close()
  server.close()
  loop.close()

test "test_serve_static_rejects_path_traversal":
  let resp = testServeStaticRejects(20093, "/static/../../../etc/passwd")
  assert "403" in resp or "Forbidden" in resp,
    "path traversal should be rejected with 403, got: '" & resp & "'"

test "test_serve_static_rejects_tilde":
  let resp = testServeStaticRejects(20094, "/static/~user/file")
  assert "403" in resp or "Forbidden" in resp,
    "tilde path should be rejected with 403, got: '" & resp & "'"

test "test_max_pipeline_depth_enforced":
  var requestCount = 0
  let loop = newLoop()

  let server = newHttpServer(loop)
  server.maxPipelineDepth = 2
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      inc requestCount
      res.status(Http200).send("OK")

  server.listen("127.0.0.1", 20095)

  let pipelined = "GET /1 HTTP/1.1\r\nHost: localhost\r\n\r\n" &
                  "GET /2 HTTP/1.1\r\nHost: localhost\r\n\r\n" &
                  "GET /3 HTTP/1.1\r\nHost: localhost\r\n\r\n" &
                  "GET /4 HTTP/1.1\r\nHost: localhost\r\n\r\n"

  discard loop.addTimer(50) do (id: int):
    loop.connect("127.0.0.1", 20095,
      onConnect = proc(conn: Connection) =
        discard conn.send(pipelined)
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        discard
      ,
      onClose = proc(conn: Connection) =
        server.close()
        loop.stop()
    )

  discard loop.addTimer(500) do (id: int):
    server.close()
    loop.stop()

  loop.run()
  loop.close()
  assert requestCount == 2,
    "only 2 requests should be dispatched with maxPipelineDepth=2, got " & $requestCount

# ══════════════════════════════════════════════════════════════════════
# Section 3: WebSocket Security
# ══════════════════════════════════════════════════════════════════════

proc makeWsTestConn(loop: Loop): Connection =
  result = newConnection(SocketHandle(-1), loop, nil, nil, 0)
  result.state = Connected
  result.sendFileFd = -1

test "test_ws_rejects_large_frame":
  let loop = newLoop()
  let conn = makeWsTestConn(loop)
  let ws = newWsConnection(conn, maxFrameSize = 1024)
  assert ws.maxFrameSize == 1024
  let mask = [0x00'u8, 0x00, 0x00, 0x00]
  var frame = @[0x82'u8, 0xFE, 0x04, 0x01]
  for m in mask: frame.add(m)
  ws.parseWsFrames(frame)
  assert ws.conn.state != Connected,
    "connection should be closed after oversized frame"
  loop.close()

test "test_ws_accepts_normal_frame":
  let loop = newLoop()
  let conn = makeWsTestConn(loop)
  var receivedData: seq[byte] = @[]
  let ws = newWsConnection(conn, maxFrameSize = 1024)
  ws.onMessage = proc(wsock: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
    receivedData = @data
  let mask = [0x00'u8, 0x00, 0x00, 0x00]
  var frame = @[0x82'u8, 0x82]
  for m in mask: frame.add(m)
  frame.add('h'.byte xor mask[0]); frame.add('i'.byte xor mask[1])
  ws.parseWsFrames(frame)
  assert ws.conn.state == Connected,
    "connection should remain open for small frame"
  loop.close()

test "test_ws_rejects_64bit_large_frame":
  let loop = newLoop()
  let conn = makeWsTestConn(loop)
  let ws = newWsConnection(conn, maxFrameSize = 1024)
  let mask = [0x00'u8, 0x00, 0x00, 0x00]
  var frame = @[0x82'u8, 0xFF, 0, 0, 0, 0, 0, 0, 0x07, 0xD0]
  for m in mask: frame.add(m)
  ws.parseWsFrames(frame)
  assert ws.conn.state != Connected,
    "connection should be closed for 64-bit oversized frame"
  loop.close()

test "test_ws_rejects_unmasked_frame":
  let loop = newLoop()
  let conn = makeWsTestConn(loop)
  let ws = newWsConnection(conn, maxFrameSize = 1024)
  # Unmasked binary frame — RFC 6455 requires client-to-server masking
  var frame: seq[byte] = @[0x82'u8, 0x02, 'h'.byte, 'i'.byte]
  ws.parseWsFrames(frame)
  assert ws.conn.state != Connected,
    "unmasked frame should be rejected"
  loop.close()

test "test_ws_rejects_control_frame_too_large":
  let loop = newLoop()
  let conn = makeWsTestConn(loop)
  let ws = newWsConnection(conn, maxFrameSize = 10 * 1024 * 1024)
  let mask = [0x00'u8, 0x00, 0x00, 0x00]
  # Ping frame with 126-byte payload (control frames max is 125)
  var frame = @[0x89'u8, 0xFE, 0x00, 0x7E]
  for m in mask: frame.add(m)
  for i in 0..<126: frame.add(0)
  ws.parseWsFrames(frame)
  assert ws.conn.state != Connected,
    "control frame over 125 bytes should be rejected"
  loop.close()

test "test_ws_rejects_invalid_close_code":
  let loop = newLoop()
  let conn = makeWsTestConn(loop)
  let ws = newWsConnection(conn, maxFrameSize = 1024)
  let mask = [0x00'u8, 0x00, 0x00, 0x00]
  # Close frame with reserved code 1004
  var frame = @[0x88'u8, 0x82, 0x03, 0xEC]  # close code 1004
  for m in mask: frame.add(m)
  frame.add(0x03 xor mask[0]); frame.add(0xEC xor mask[1])
  ws.parseWsFrames(frame)
  assert ws.conn.state != Connected,
    "invalid close code should be rejected"
  loop.close()

test "test_ws_rejects_one_byte_close":
  let loop = newLoop()
  let conn = makeWsTestConn(loop)
  let ws = newWsConnection(conn, maxFrameSize = 1024)
  let mask = [0x00'u8, 0x00, 0x00, 0x00]
  # Close frame with 1-byte payload (invalid per RFC)
  var frame = @[0x88'u8, 0x81]
  for m in mask: frame.add(m)
  frame.add(0x00 xor mask[0])
  ws.parseWsFrames(frame)
  assert ws.conn.state != Connected,
    "close frame with 1-byte payload should be rejected"
  loop.close()

test "test_ws_rejects_data_frame_during_fragmentation":
  let loop = newLoop()
  let conn = makeWsTestConn(loop)
  let ws = newWsConnection(conn, maxFrameSize = 1024)
  let mask = [0x00'u8, 0x00, 0x00, 0x00]
  # First fragment: non-fin text frame
  var frag = @[0x01'u8, 0x81]    # FIN=0, opcode=1
  for m in mask: frag.add(m)
  frag.add(0x41 xor mask[0])     # "A"
  ws.parseWsFrames(frag)
  assert ws.conn.state == Connected, "first fragment should be accepted"
  # Second frame: new text frame without finishing (should error)
  var frame = @[0x81'u8, 0x81]
  for m in mask: frame.add(m)
  frame.add(0x42 xor mask[0])    # "B"
  ws.parseWsFrames(frame)
  assert ws.conn.state != Connected,
    "data frame during fragmentation should be rejected"
  loop.close()

# ══════════════════════════════════════════════════════════════════════
# Section 4: DoS Simulation Tests
# ══════════════════════════════════════════════════════════════════════

test "test_slow_loris_headers":
  let raw = "GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: header\r\n\r\n"
  let parser = newHttpParser()
  # Feed one byte at a time — simulate slow header attack
  for i in 0 ..< raw.len:
    discard parser.feed(raw[i .. i])
  assert parser.isComplete(), "slow headers should parse correctly"
  let req = parser.getRequest()
  assert req.getPath() == "/"

test "test_slow_loris_body":
  let body = "Hello, World!"
  let headers = "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\n\r\n"
  let full = headers & body
  let parser = newHttpParser()
  # Feed one byte at a time through the entire request
  for i in 0 ..< full.len:
    discard parser.feed(full[i .. i])
  assert parser.isComplete(), "slow body should parse correctly"
  let req = parser.getRequest()
  assert req.getBodyString() == "Hello, World!"

test "test_many_small_body_chunks":
  let data = repeat('X', 1000)
  let raw = "POST /chunks HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000\r\n\r\n" & data
  let parser = newHttpParser()
  # Feed in 1-byte chunks
  for i in 0 ..< raw.len:
    discard parser.feed(raw[i .. i])
  assert parser.isComplete(), "many small chunks should parse correctly"
  let req = parser.getRequest()
  assert req.getBody().len == 1000

test "test_content_length_mismatch_handled":
  # Send Content-Length: 5 with actual body of 20 bytes
  let body = "HelloExtraDataHere!"
  let request = "POST /mismatch HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n" & body
  let parser = newHttpParser()
  parser.feed(request)
  assert parser.isComplete(), "parser should complete with CL=5"
  let req = parser.getRequest()
  assert req.getBodyString() == "Hello",
    "body should be truncated to Content-Length"
  assert req.parser.getRemainingData().len > 0,
    "extra body bytes should remain as remaining data"

test "test_many_pipelined_requests":
  var raw = ""
  for i in 0 ..< 50:
    raw.add("GET /" & $i & " HTTP/1.1\r\nHost: localhost\r\n\r\n")
  let parser = newHttpParser()
  parser.feed(raw)
  assert parser.isComplete(), "pipelined requests should parse"
  var count = 0
  while parser.isComplete():
    discard parser.getRequest()
    inc count
    parser.resetForNext()
    discard parser.feed(@[])
  assert count == 50,
    "should parse all 50 pipelined requests, got " & $count

test "test_rejects_body_exceeding_limit_without_allocation":
  # Send Content-Length of 1GB with maxBodySize=1MB
  # Verify immediate rejection without allocating 1GB
  let headers = "POST /big HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1073741824\r\n\r\n"
  let parser = newHttpParser()
  parser.maxBodySize = 1_048_576  # 1MB
  parser.feed(headers)
  assert parser.isError(), "should immediately error on oversized Content-Length"
  assert parser.error() == Http413

# ══════════════════════════════════════════════════════════════════════
# Section 5: Rate Limiter Tests
# ══════════════════════════════════════════════════════════════════════

test "test_ratelimit_allows_within_window":
  let loop = newLoop()
  let rl = newRateLimiter(loop, maxRequests = 3, windowMs = 60_000)
  assert rl.allow("1.2.3.4"), "first request should be allowed"
  assert rl.allow("1.2.3.4"), "second request should be allowed"
  assert rl.allow("1.2.3.4"), "third request should be allowed"
  loop.close()

test "test_ratelimit_denies_excess":
  let loop = newLoop()
  let rl = newRateLimiter(loop, maxRequests = 3, windowMs = 60_000)
  assert rl.allow("1.2.3.4")
  assert rl.allow("1.2.3.4")
  assert rl.allow("1.2.3.4")
  assert not rl.allow("1.2.3.4"), "4th request should be denied"
  loop.close()

test "test_ratelimit_separate_ips":
  let loop = newLoop()
  let rl = newRateLimiter(loop, maxRequests = 2, windowMs = 60_000)
  assert rl.allow("1.2.3.4")
  assert rl.allow("1.2.3.4")
  assert not rl.allow("1.2.3.4")
  assert rl.allow("5.6.7.8"), "different IP should be allowed independently"
  loop.close()

test "test_ratelimit_empty_ip_allowed":
  let loop = newLoop()
  let rl = newRateLimiter(loop, maxRequests = 1, windowMs = 60_000)
  assert rl.allow(""), "empty IP should be allowed (not rate-limited)"
  assert rl.allow(""), "empty IP should always be allowed"
  loop.close()

test "test_ratelimit_zero_max_disabled":
  let loop = newLoop()
  let rl = newRateLimiter(loop, maxRequests = 0, windowMs = 60_000)
  assert rl.allow("1.2.3.4"), "maxRequests=0 means unlimited"
  assert rl.allow("1.2.3.4")
  loop.close()
