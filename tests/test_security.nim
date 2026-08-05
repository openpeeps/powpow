## tests/test_security.nim — Security tests for powpow.
##
## Covers: body size limits, overflow protection, DoS resistance,
##         connection limits, WebSocket frame limits, path traversal.
## All tests are deterministic — no timing-dependent assertions.
## Parser-level tests use zero-copy access patterns.

import ../src/powpow
import std/[unittest, strutils, httpcore, os]

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

test "test_streaming_body_enforces_max_size":
  # Chunked streaming bodies were previously forwarded to onBodyData with no
  # size accounting — an attacker could stream unbounded data to disk/RAM.
  # Verify maxBodySize is now enforced (413) in streaming mode.
  let rawHeaders = "POST /x HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
  var streamed = 0
  let parser = newHttpParser()
  parser.maxBodySize = 100
  parser.onBodyData = proc(data: openArray[byte]; done: bool) {.closure.} =
    streamed += data.len
  parser.feed(rawHeaders)
  assert parser.phase == PhaseBody, "headers should parse into the body phase"
  parser.feed(repeat('X', 200))
  assert parser.isError(), "chunked streaming must enforce maxBodySize"
  assert parser.error() == Http413

test "test_content_length_overflow_handled_safely":
  let raw = "POST /overflow HTTP/1.1\r\nHost: localhost\r\nContent-Length: 99999999999999999999\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  assert parser.isError()
  assert parser.error() == Http413

test "test_content_length_exact_boundary_rejected":
  # Content-Length = 2^63 (9223372036854775808) — the exact boundary where
  # `num * 10 + digit` wraps past high(int). Previously the `num > high div 10`
  # check let this value through: it raised OverflowDefect in release builds
  # (crash/DoS) and wrapped to a negative contentLength in -d:danger builds
  # (request-smuggling/desync primitive).
  let raw = "POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9223372036854775808\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  assert parser.isError(), "exact-boundary CL must be rejected, not crash or wrap"
  assert parser.error() == Http413
  assert parser.contentLength == -1, "contentLength must stay -1 on error"

test "test_content_length_max_int64_accepted":
  # The largest representable value must still parse (no false positive).
  let raw = "POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9223372036854775807\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  assert not parser.isError(), "max int64 CL should not be rejected"
  assert parser.contentLength == high(int)

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
  let longLine = repeat('A', 9000)
  let raw = "GET /" & longLine & " HTTP/1.1\r\nHost: localhost\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  assert parser.isError(), "oversized request line should error"
  assert parser.error() == Http414

test "test_oversized_header_packet_rejected_before_allocation":
  # A single packet whose header section vastly exceeds the caps must be
  # rejected without first growing the parser buffer to its size. The parser
  # buffer must stay small after the feed.
  let huge = repeat('X', 1024 * 1024)   # 1 MB of header bytes in one packet
  let raw = "GET / HTTP/1.1\r\nHost: localhost\r\nX-Huge: " & huge & "\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  assert parser.isError(), "oversized header packet should error immediately"
  assert parser.error() == Http431
  assert parser.buf.len < 64 * 1024,
    "parser buffer must not grow to match the hostile packet (len=" & $parser.buf.len & ")"

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

test "test_non_chunked_transfer_encoding_does_not_enable_chunked":
  # Previously ANY Transfer-Encoding value >= 7 chars enabled chunked framing
  # (e.g. "gzipfoo"). Only a final "chunked" token may do so — a non-chunked TE
  # must not make the parser wait for a chunked body.
  let raw = "POST /x HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzipfoo\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  assert parser.isComplete(),
    "non-chunked TE value must not enable chunked framing (request completes)"

test "test_transfer_encoding_chunked_as_final_token_enabled":
  # "gzip, chunked" — chunked is final → chunked framing enabled.
  let raw = "POST /x HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip, chunked\r\n\r\n" &
            "3\r\nabc\r\n0\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  assert parser.isComplete(), "chunked body should parse when TE ends in chunked"

test "test_leading_whitespace_header_rejected":
  # obs-fold / leading-whitespace header lines are a smuggling hazard and must
  # be rejected (previously tolerated as generic headers).
  let raw = "GET /x HTTP/1.1\r\nHost: localhost\r\n Transfer-Encoding: chunked\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  assert parser.isError(), "leading-whitespace header line should be rejected"
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

when not defined(windows):
  test "test_multipart_per_file_limit_413":
    # A multipart upload whose file part exceeds server.maxFileSize must be
    # rejected with 413 (independently of the total body cap).
    var responseData: seq[byte] = @[]
    var clientConn: Connection = nil
    let loop = newLoop()
  
    let server = newHttpServer(loop)
    server.maxFileSize = 100
    server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
      res.status(Http200).send("OK")
  
    server.listen("127.0.0.1", 20097)
  
    let boundary = "MyBoundary"
    let fileContent = repeat('X', 5000)  # 5 KB file part, cap is 100 bytes
    let body = "--" & boundary & "\r\n" &
               "Content-Disposition: form-data; name=\"file\"; filename=\"big.bin\"\r\n" &
               "Content-Type: application/octet-stream\r\n\r\n" &
               fileContent & "\r\n" &
               "--" & boundary & "--\r\n"
    let headers = "POST /upload HTTP/1.1\r\nHost: localhost\r\n" &
                  "Content-Type: multipart/form-data; boundary=" & boundary & "\r\n" &
                  "Content-Length: " & $body.len & "\r\n\r\n"
  
    discard loop.addTimer(50) do (id: int):
      loop.connect("127.0.0.1", 20097,
        onConnect = proc(conn: Connection) =
          clientConn = conn
          # Send headers + a partial body so the upload is still incoming and
          # the auto-streaming (with the per-file cap) activates. The file part
          # already exceeds the cap inside this chunk, so the server must reject
          # with 413 without requiring the rest of the body. (A second pending
          # send is deliberately avoided: if the client still has bytes queued
          # when the server responds and closes, the client's failed write can
          # tear down its socket before the response is read on some platforms.)
          discard conn.send(headers & body[0 ..< 512])
        ,
        onData = proc(conn: Connection, data: openArray[byte]) =
          responseData.add(@data)
        ,
      )
  
    discard loop.addTimer(5000) do (id: int):
      if clientConn != nil: clientConn.close()
      server.close()
      loop.stop()
  
    # Poll until we have response data or timeout. Driving the loop with
    # poll(0) (instead of run()) avoids stopping on the connection-close
    # event before the pending read data is drained, which differs between
    # kqueue (macOS) and epoll (Linux).
    var polls = 0
    while responseData.len == 0 and polls < 500000:
      loop.poll(0)
      inc polls
    if clientConn != nil: clientConn.close()
    server.close()
    loop.close()
    let resp = cast[string](responseData)
    assert "413" in resp,
      "oversized multipart file part should be rejected with 413, got: '" & resp & "'"

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

proc testServeFileSiblingEscape(port: int): string =
  ## Serves a file from a *sibling* directory whose name shares the fsRoot
  ## prefix (fsRoot="..._root", sibling="..._root2"). The guard must reject it.
  var responseData: seq[byte] = @[]
  let loop = newLoop()

  let fsRoot = os.getTempDir() / "powpow_test_root"
  removeDir(fsRoot)
  removeDir(fsRoot & "2")
  createDir(fsRoot)
  createDir(fsRoot & "2")
  writeFile(fsRoot & "2" / "secret.txt", "TOP-SECRET")

  let server = newHttpServer(loop)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      if not serveFile(res, req, fsRoot & "2" / "secret.txt", fsRoot = fsRoot):
        res.sendError(Http404, "Not Found")

  server.listen("127.0.0.1", port)

  discard loop.addTimer(50) do (id: int):
    loop.connect("127.0.0.1", port,
      onConnect = proc(conn: Connection) =
        discard conn.send("GET /anything HTTP/1.1\r\nHost: localhost\r\n\r\n")
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
  removeDir(fsRoot)
  removeDir(fsRoot & "2")
  result = cast[string](responseData)

test "test_serve_file_rejects_sibling_prefix_escape":
  let resp = testServeFileSiblingEscape(20095)
  assert "403" in resp or "Forbidden" in resp,
    "sibling-prefix path must be rejected with 403, got: '" & resp & "'"

proc testSendFileHugeHeader(port: int): string =
  ## sendFile used to build its response headers into a fixed `array[768, byte]`
  ## via unchecked copyMem. A long custom header (or a long Content-Disposition
  ## filename) overflowed the stack buffer. Verify a large header is sent intact.
  var responseData: seq[byte] = @[]
  let loop = newLoop()
  let f = getTempDir() / "powpow_sendfile_huge.txt"
  writeFile(f, "FILE-BODY")

  let server = newHttpServer(loop)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      res.header("X-Huge", repeat('A', 5000))
      res.sendFile(f, req, closeConn = false, contentDisposition = true)
  server.listen("127.0.0.1", port)

  discard loop.addTimer(50) do (id: int):
    loop.connect("127.0.0.1", port,
      onConnect = proc(conn: Connection) =
        discard conn.send("GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n")
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
  removeFile(f)
  result = cast[string](responseData)

test "test_send_file_huge_header_no_overflow":
  let resp = testSendFileHugeHeader(20096)
  assert "200 OK" in resp,
    "should serve file with huge header, got: '" & resp[0 ..< min(resp.len, 120)] & "'"
  assert "X-Huge" in resp, "huge custom header must be present in response"

when not defined(windows):
  test "test_serve_file_rejects_symlink_escape":
    # A symlink inside fsRoot pointing outside must be rejected (403).
    let tmpRoot = getTempDir() / "powpow_symlink_root"
    removeDir(tmpRoot)
    createDir(tmpRoot)
    let outside = getTempDir() / "powpow_symlink_secret.txt"
    writeFile(outside, "SECRET-OUTSIDE")
    createSymlink(outside, tmpRoot / "leak.txt")
    defer:
      removeDir(tmpRoot)
      removeFile(outside)

    var responseData: seq[byte] = @[]
    let loop = newLoop()
    let server = newHttpServer(loop)
    server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
      {.gcsafe.}:
        if not serveFile(res, req, tmpRoot / "leak.txt", fsRoot = tmpRoot):
          res.sendError(Http404, "Not Found")
    server.listen("127.0.0.1", 20100)

    discard loop.addTimer(50) do (id: int):
      loop.connect("127.0.0.1", 20100,
        onConnect = proc(conn: Connection) =
          discard conn.send("GET /leak HTTP/1.1\r\nHost: localhost\r\n\r\n")
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
    let resp = cast[string](responseData)
    assert "403" in resp or "Forbidden" in resp,
      "symlink escape should be rejected with 403, got: '" & resp & "'"
    assert "SECRET-OUTSIDE" notin resp,
      "symlink target content must not be served"

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

test "test_ws_rejects_64bit_frame_unlimited_mode":
  # maxFrameSize == 0 (unlimited) must still not allocate a huge buffer:
  # a 2^63 payload length must be rejected against the hard cap, not OOM.
  let loop = newLoop()
  let conn = makeWsTestConn(loop)
  let ws = newWsConnection(conn, maxFrameSize = 0)
  let mask = [0x00'u8, 0x00, 0x00, 0x00]
  var frame = @[0x82'u8, 0xFF, 0x80, 0, 0, 0, 0, 0, 0, 0]  # 64-bit length = 2^63
  for m in mask: frame.add(m)
  ws.parseWsFrames(frame)
  assert ws.conn.state != Connected,
    "64-bit oversized frame must be rejected even when maxFrameSize == 0"
  loop.close()

test "test_ws_rejects_huge_fragmented_message_unlimited_mode":
  # Fragmented message whose first fragment exceeds the hard cap must be
  # rejected even when maxFrameSize == 0 (prevents unbounded assembleBuf growth).
  let loop = newLoop()
  let conn = makeWsTestConn(loop)
  let ws = newWsConnection(conn, maxFrameSize = 0)
  let mask = [0x00'u8, 0x00, 0x00, 0x00]
  # First fragment announces a 600MB payload (above the 512MB hard cap)
  var frame = @[0x02'u8, 0xFF, 0, 0, 0, 0, 0x24, 0, 0, 0]  # 64-bit length = 600MB
  for m in mask: frame.add(m)
  ws.parseWsFrames(frame)
  assert ws.conn.state != Connected,
    "oversized first fragment must be rejected in unlimited mode"
  loop.close()

test "test_ws_handshake_timeout_closes_stalled_connections":
  # A client that connects and never sends handshake data must be closed by the
  # handshake timeout (previously handshake sessions grew unboundedly — a
  # handshake-stall memory/resource DoS).
  let loop = newLoop()
  var wss = newWsServer(loop)
  wss.handshakeTimeoutMs = 120
  wss.listen("127.0.0.1", 29960)

  var closed = false
  loop.connect("127.0.0.1", 29960,
    onConnect = proc(conn: Connection) =
      discard  # stall: send nothing, never complete the HTTP upgrade
    ,
    onData = proc(conn: Connection, data: openArray[byte]) = discard,
    onClose = proc(conn: Connection) = closed = true,
  )

  var polls = 0
  while not closed and polls < 10000:
    loop.poll(1)
    inc polls
  assert closed, "stalled handshake connection should be closed by timeout"
  assert wss.handshakeCount() == 0,
    "stalled handshake sessions must be cleaned up"
  wss.close()
  loop.close()

test "test_ws_handshake_sessions_bounded":
  # maxHandshakeSessions caps in-flight handshakes; excess connections are
  # rejected at accept time.
  let loop = newLoop()
  var wss = newWsServer(loop)
  wss.handshakeTimeoutMs = 2000
  wss.maxHandshakeSessions = 2
  wss.listen("127.0.0.1", 29961)

  for i in 0 ..< 3:
    loop.connect("127.0.0.1", 29961,
      onConnect = proc(conn: Connection) =
        discard  # stall the handshake
      ,
      onData = proc(conn: Connection, data: openArray[byte]) = discard,
      onClose = proc(conn: Connection) = discard,
    )
    # drive the loop so the accept callback runs and the cap is enforced
    var p = 0
    while p < 400:
      loop.poll(1)
      inc p

  # the cap is 2, so at most 2 sessions survive at once
  assert wss.handshakeCount() <= 2,
    "handshake sessions must be bounded, got " & $wss.handshakeCount()
  wss.close()
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

test "test_idle_keepalive_timeout_closes_connection":
  # A client that connects and then goes idle must be closed after keepAliveMs.
  # Previously keepAliveMs/readTimeoutMs were declared but never enforced,
  # leaving idle keep-alive connections to accumulate unbounded (resource
  # exhaustion). Timing-based: short timeout + bounded poll window.
  let loop = newLoop()
  var server = newHttpServer(loop)
  server.setKeepAliveTimeout(120)
  server.readTimeoutMs = 120
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http200).send("ok")
  server.listen("127.0.0.1", 19901)

  var closedByServer = false
  loop.connect("127.0.0.1", 19901,
    onConnect = proc(conn: Connection) =
      # Partial request, then idle — the server must time the connection out.
      discard conn.send("GET / HTTP/1.1\r\nHost: localhost\r\n")
    ,
    onData = proc(conn: Connection, data: openArray[byte]) = discard,
    onClose = proc(conn: Connection) = closedByServer = true,
  )

  var polls = 0
  while not closedByServer and polls < 10000:
    loop.poll(1)
    inc polls
  assert closedByServer, "idle connection should be closed by keep-alive timeout"
  server.close()
  loop.close()

test "test_read_timeout_closes_slow_request":
  # A client that sends a partial request line and then stalls (slowloris)
  # must be closed after readTimeoutMs.
  let loop = newLoop()
  var server = newHttpServer(loop)
  server.setKeepAliveTimeout(2000)
  server.readTimeoutMs = 120
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http200).send("ok")
  server.listen("127.0.0.1", 19902)

  var closed = false
  loop.connect("127.0.0.1", 19902,
    onConnect = proc(conn: Connection) =
      discard conn.send("GET / HTT")   # incomplete request line, never finished
    ,
    onData = proc(conn: Connection, data: openArray[byte]) = discard,
    onClose = proc(conn: Connection) = closed = true,
  )
  var polls = 0
  while not closed and polls < 10000:
    loop.poll(1)
    inc polls
  assert closed, "stalled request should be closed by read timeout"
  assert polls < 1500,
    "connection should be closed by readTimeoutMs (120ms), not keepAliveMs (2000ms)"
  server.close()
  loop.close()

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
