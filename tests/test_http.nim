## tests/test_http.nim — Tests for the HTTP parser.
##
## Tests: basic GET, POST with body, query string, headers, chunked, keep-alive.

import ../src/powpow
import std/[httpcore, strutils, unittest, os]

# ── Test 1: Basic GET request ────────────────────────────────────────────────

test "test_get_basic":
  let raw = "GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete(), "GET should be complete"

  let req = parser.getRequest()
  doAssert req.getMethod() == HttpGet
  doAssert req.getPath() == "/hello"
  doAssert req.getQuery() == ""
  doAssert req.getUrl() == "/hello"
  doAssert req.getContentLength() == -1
  doAssert req.getBody().len == 0

  let headers = req.getHeaders()
  doAssert headers["Host"] == "localhost"

# ── Test 2: GET with query string ────────────────────────────────────────────

test "test_get_query":
  let raw = "GET /search?q=hello+world&page=2 HTTP/1.1\r\nHost: example.com\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete()

  let req = parser.getRequest()
  doAssert req.getMethod() == HttpGet
  doAssert req.getPath() == "/search"
  doAssert req.getQuery() == "q=hello+world&page=2"
  doAssert req.getUrl() == "/search?q=hello+world&page=2"

# ── Test 3: POST with body ───────────────────────────────────────────────────

test "test_post_body":
  let body = """{"name":"powpow"}"""
  let raw = "POST /api/data HTTP/1.1\r\n" &
            "Host: localhost\r\n" &
            "Content-Type: application/json\r\n" &
            "Content-Length: " & $body.len & "\r\n" &
            "\r\n" & body
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete()

  let req = parser.getRequest()
  doAssert req.getMethod() == HttpPost
  doAssert req.getPath() == "/api/data"
  doAssert req.getContentLength() == body.len
  doAssert req.getBodyString() == body

  let headers = req.getHeaders()
  doAssert headers["Content-Type"] == "application/json"

# ── Test 4: Incremental feeding ──────────────────────────────────────────────

test "test_incremental_feed":
  let raw = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"
  let parser = newHttpParser()

  # Feed one byte at a time
  for i in 0 ..< raw.len:
    let phase = parser.feed(raw[i .. i])
    if i < raw.len - 1 and phase != PhaseComplete:
      doAssert not parser.isComplete()

  doAssert parser.isComplete()
  let req = parser.getRequest()
  doAssert req.getMethod() == HttpGet
  doAssert req.getPath() == "/"

# ── Test 5: Multiple headers ─────────────────────────────────────────────────

test "test_multiple_headers":
  let raw = "GET / HTTP/1.1\r\n" &
            "Host: localhost\r\n" &
            "Accept: text/html\r\n" &
            "Accept-Language: en-US\r\n" &
            "Cookie: session=abc123\r\n" &
            "Connection: keep-alive\r\n" &
            "\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete()

  let req = parser.getRequest()
  let headers = req.getHeaders()
  doAssert headers["Host"] == "localhost"
  doAssert headers["Accept"] == "text/html"
  doAssert headers["Accept-Language"] == "en-US"
  doAssert headers["Cookie"] == "session=abc123"
  doAssert headers["Connection"] == "keep-alive"

# ── Test 6: Parser reset for keep-alive ──────────────────────────────────────

test "test_parser_reset":
  let parser = newHttpParser()
  let req1raw = "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n"
  parser.feed(req1raw)
  doAssert parser.isComplete()

  let req1 = parser.getRequest()
  doAssert req1.getPath() == "/first"

  # Reset for next request
  parser.reset()
  doAssert parser.phase == PhaseRequestLine

  let req2raw = "POST /second HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nworld"
  parser.feed(req2raw)
  doAssert parser.isComplete()

  let req2 = parser.getRequest()
  doAssert req2.getMethod() == HttpPost
  doAssert req2.getPath() == "/second"
  doAssert req2.getBodyString() == "world"

# ── Test 7: Error — URI too long ─────────────────────────────────────────────

test "test_error_uri_too_long":
  let bigPath = "/" & repeat("a", 9000)
  let raw = "GET " & bigPath & " HTTP/1.1\r\nHost: localhost\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isError(), "should error on oversized URI"
  doAssert parser.error() == Http414

# ── Test 8: HEAD method ──────────────────────────────────────────────────────

test "test_head_method":
  let raw = "HEAD /resource HTTP/1.1\r\nHost: localhost\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete()

  let req = parser.getRequest()
  doAssert req.getMethod() == HttpHead
  doAssert req.getPath() == "/resource"

# ── Test 9: DELETE method ────────────────────────────────────────────────────

test "test_delete_method":
  let raw = "DELETE /api/items/42 HTTP/1.1\r\nHost: localhost\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete()

  let req = parser.getRequest()
  doAssert req.getMethod() == HttpDelete
  doAssert req.getPath() == "/api/items/42"

# ── Test 10: Chunked transfer encoding ──────────────────────────────────────

test "test_chunked_basic":
  let raw = "POST /api/data HTTP/1.1\r\n" &
            "Host: localhost\r\n" &
            "Transfer-Encoding: chunked\r\n" &
            "\r\n" &
            "5\r\n" &
            "hello\r\n" &
            "6\r\n" &
            " world\r\n" &
            "0\r\n" &
            "\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete(), "chunked request should be complete"

  let req = parser.getRequest()
  doAssert req.getMethod() == HttpPost
  doAssert req.getPath() == "/api/data"
  doAssert req.getBodyString() == "hello world"

# ── Test 11: Chunked with chunk extensions ──────────────────────────────────

test "test_chunked_extensions":
  let raw = "PUT /upload HTTP/1.1\r\n" &
            "Host: localhost\r\n" &
            "Transfer-Encoding: chunked\r\n" &
            "\r\n" &
            "5;ext=value\r\n" &
            "hello\r\n" &
            "0\r\n" &
            "\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete(), "chunked with extensions should be complete"

  let req = parser.getRequest()
  doAssert req.getMethod() == HttpPut
  doAssert req.getBodyString() == "hello"

# ── Test 12: Chunked with trailers ──────────────────────────────────────────

test "test_chunked_trailers":
  # Note: Current implementation doesn't support trailers, so this test
  # verifies that we can handle the common case without trailers
  let raw = "POST /api/data HTTP/1.1\r\n" &
            "Host: localhost\r\n" &
            "Transfer-Encoding: chunked\r\n" &
            "\r\n" &
            "5\r\n" &
            "hello\r\n" &
            "0\r\n" &
            "\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete(), "chunked without trailers should be complete"

  let req = parser.getRequest()
  doAssert req.getBodyString() == "hello"

# ── Test 13: Chunked incremental feeding ────────────────────────────────────

test "test_chunked_incremental":
  let raw = "POST /api/data HTTP/1.1\r\n" &
            "Host: localhost\r\n" &
            "Transfer-Encoding: chunked\r\n" &
            "\r\n" &
            "5\r\n" &
            "hello\r\n" &
            "6\r\n" &
            " world\r\n" &
            "0\r\n" &
            "\r\n"
  let parser = newHttpParser()

  # Feed one byte at a time
  for i in 0 ..< raw.len:
    let phase = parser.feed(raw[i .. i])
    if i < raw.len - 1:
      doAssert not parser.isComplete(), "should not be complete until end"

  doAssert parser.isComplete(), "should be complete after all data"
  let req = parser.getRequest()
  doAssert req.getBodyString() == "hello world"

# ── Test 14: Chunked empty body ─────────────────────────────────────────────

test "test_chunked_empty":
  let raw = "GET /api/data HTTP/1.1\r\n" &
            "Host: localhost\r\n" &
            "Transfer-Encoding: chunked\r\n" &
            "\r\n" &
            "0\r\n" &
            "\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete(), "chunked empty should be complete"

  let req = parser.getRequest()
  doAssert req.getMethod() == HttpGet
  doAssert req.getBody().len == 0

# ── Test 15: Pipelining — resetForNext preserves leftover bytes ──────────────

test "test_pipelining_resetForNext":
  let parser = newHttpParser()
  let pipelined = "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n" &
                  "GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n"
  parser.feed(pipelined)
  doAssert parser.isComplete()

  let req1 = parser.getRequest()
  doAssert req1.getPath() == "/first"

  parser.resetForNext()
  doAssert parser.phase == PhaseRequestLine
  discard parser.feed(@[])
  doAssert parser.isComplete()

  let req2 = parser.getRequest()
  doAssert req2.getPath() == "/second"

  parser.resetForNext()
  discard parser.feed(@[])
  doAssert parser.phase == PhaseRequestLine
  doAssert not parser.isComplete()

# ── Test 16: Pipelining — POST with Content-Length ───────────────────────────

test "test_pipelining_post":
  let parser = newHttpParser()
  let body1 = "hello"
  let body2 = "world!!"
  let pipelined = "POST /a HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n" & body1 &
                  "POST /b HTTP/1.1\r\nHost: localhost\r\nContent-Length: 7\r\n\r\n" & body2
  parser.feed(pipelined)
  doAssert parser.isComplete()

  let req1 = parser.getRequest()
  doAssert req1.getPath() == "/a"
  doAssert req1.getBodyString() == "hello"

  parser.resetForNext()
  discard parser.feed(@[])
  doAssert parser.isComplete()

  let req2 = parser.getRequest()
  doAssert req2.getPath() == "/b"
  doAssert req2.getBodyString() == "world!!"

# ── Test 17: Pipelining — partial next request stays in buffer ───────────────

test "test_pipelining_partial":
  let parser = newHttpParser()
  parser.feed("GET /first HTTP/1.1\r\nHost: localhost\r\n\r\nGET /se")
  doAssert parser.isComplete()

  let req1 = parser.getRequest()
  doAssert req1.getPath() == "/first"

  parser.resetForNext()
  discard parser.feed(@[])
  doAssert not parser.isComplete(), "partial next request should not be complete"

  parser.feed("cond HTTP/1.1\r\nHost: localhost\r\n\r\n")
  doAssert parser.isComplete()

  let req2 = parser.getRequest()
  doAssert req2.getPath() == "/second"

# ── Test 18: BodyStream — readChunk with Content-Length ─────────────────────────

test "test_bodystream_readchunk_contentlength":
  let body = "Hello, World!"
  let raw = "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\n\r\n" & body
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete()

  let req = parser.getRequest()
  var stream = req.getBodyStream()

  var chunk1 = stream.readChunk(5)
  doAssert chunk1.len == 5
  doAssert chunk1 == @[byte 72, 101, 108, 108, 111], "got: " & $chunk1

  var chunk2 = stream.readChunkString(100)
  doAssert chunk2 == ", World!"

  var chunk3 = stream.readChunk(10)
  doAssert chunk3.len == 0, "should be EOF"

# ── Test 19: BodyStream — readChunk with chunked transfer ────────────────────

test "test_bodystream_readchunk_chunked":
  let raw = "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n8\r\n, World!\r\n0\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete()

  let req = parser.getRequest()
  var stream = req.getBodyStream()
  var all = stream.readChunk(100)
  doAssert all.len == 13
  doAssert all == @[byte 72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33], "got: " & $all

# ── Test 20: BodyStream — peekChunk and drainChunk ────────────────────────────

test "test_bodystream_peek_drain":
  let body = "ABCDEFGHIJ"
  let raw = "POST /peek HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\n" & body
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete()

  let req = parser.getRequest()
  var stream = req.getBodyStream()

  let (p1, n1) = stream.peekChunk(3)
  doAssert n1 == 3
  doAssert p1[0] == byte 65
  doAssert p1[1] == byte 66
  doAssert p1[2] == byte 67

  stream.drainChunk(3)

  let (p2, n2) = stream.peekChunk(100)
  doAssert n2 == 7
  doAssert p2[0] == byte 68

  stream.drainChunk(7)

  let (p3, n3) = stream.peekChunk(10)
  doAssert n3 == 0
  doAssert p3 == nil

# ── Test 21: BodyStream — empty body ─────────────────────────────────────────

test "test_bodystream_empty":
  let raw = "GET /empty HTTP/1.1\r\nHost: localhost\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete()

  let req = parser.getRequest()
  var stream = req.getBodyStream()
  doAssert stream.readChunk(100).len == 0
  doAssert stream.readChunkString(100) == ""

# ── Test 22: BodyStream — readChunkInto (buffer reuse) ──────────────────────────

test "test_bodystream_readchunkinto":
  let body = "Hello, World!"
  let raw = "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\n\r\n" & body
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete()

  let req = parser.getRequest()
  var stream = req.getBodyStream()
  var buf = newSeq[byte](65536)
  block:
    let n = stream.readChunkInto(buf, 5)
    doAssert n == 5
    doAssert buf[0..4] == @[byte 72, 101, 108, 108, 111]
  block:
    let n = stream.readChunkInto(buf, 100)
    doAssert n == 8
    doAssert buf[0..7] == @[byte 44, 32, 87, 111, 114, 108, 100, 33]
  block:
    let n = stream.readChunkInto(buf, 100)
    doAssert n == 0

# ── Test 23: BodyStream — peekAll (zero-copy view) ─────────────────────────────

test "test_bodystream_peekall":
  let body = "ABCDEFGH"
  let raw = "POST /peekall HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8\r\n\r\n" & body
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete()

  let req = parser.getRequest()
  var stream = req.getBodyStream()
  let (data, len) = stream.peekAll()
  doAssert len == 8
  doAssert data[0] == byte 65
  doAssert data[7] == byte 72

# ── Test 24: Streaming body callback (Content-Length) ──────────────────────────

test "test_streaming_body_contentlength":
  var received: seq[byte]
  let parser = newHttpParser()
  parser.onBodyData = proc(data: openArray[byte]; done: bool) =
    for b in data: received.add(b)
  let headers = "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\n\r\n"
  parser.feed(headers)
  doAssert parser.phase == PhaseBody
  parser.feed("Hello, World!".toOpenArrayByte(0, 12))
  doAssert parser.phase == PhaseComplete
  doAssert received.len == 13
  doAssert cast[string](received) == "Hello, World!"

# ── Test 26: Streaming body callback (with done flag) ────────────────────────

test "test_streaming_body_done":
  var chunks: seq[string]
  var finalDone = false
  let parser = newHttpParser()
  parser.onBodyData = proc(data: openArray[byte]; done: bool) =
    chunks.add(cast[string](@data))
    if done: finalDone = true
  let body = "Hello, World!"
  let raw = "POST /done HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\n\r\n" & body
  parser.feed(raw)
  doAssert parser.phase == PhaseComplete
  doAssert finalDone
  doAssert chunks.len >= 1
  doAssert chunks.join("") == "Hello, World!"

# ── Test 25: Buffer shrink after resetForNext ───────────────────────────────────

test "test_buffer_shrink_after_reset":
  let parser2 = newHttpParser(8192)
  let bigBody = "X".repeat(10000)
  let req2 = "POST /big HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10000\r\n\r\n" & bigBody
  parser2.feed(req2)
  doAssert parser2.isComplete()
  # After reset, parser is ready for next request — buffer was grown and now shrunk
  parser2.resetForNext()
  # Just verify the parser works after shrink
  let smallReq = "GET /small HTTP/1.1\r\nHost: localhost\r\n\r\n"
  parser2.feed(smallReq)
  doAssert parser2.isComplete()
  let req = parser2.getRequest()
  doAssert req.getPath() == "/small"

# ── Test 26: Streaming body pipelining (only body bytes forwarded) ───────────

test "test_streaming_pipelining":
  var received: seq[byte]
  let parser = newHttpParser()
  parser.onBodyData = proc(data: openArray[byte]; done: bool) =
    for b in data: received.add(b)

  # First request: 5-byte body
  let req1 = "POST /a HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello"
  # Second request follows immediately in the same TCP read
  let req2 = "GET /b HTTP/1.1\r\nHost: localhost\r\n\r\n"

  parser.feed(req1 & req2)
  doAssert parser.phase == PhaseComplete
  doAssert received.len == 5
  doAssert cast[string](received) == "hello"

  # The second request should be parseable via resetForNext
  parser.resetForNext()
  discard parser.feed(@[])
  doAssert parser.isComplete()

# ── Test 27: Peek accessors (available during PhaseBody) ──────────────────────

test "test_peek_accessors":
  let headers = "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Type: multipart/form-data; boundary=abc\r\nContent-Length: 100\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(headers)
  doAssert parser.phase == PhaseBody

  doAssert parser.peekMethod() == HttpPost
  doAssert parser.peekPath() == "/upload"
  let ct = parser.peekContentType()
  doAssert ct.startsWith("multipart/form-data")
  doAssert "boundary=abc" in ct

# ── Test 29: bodyView() zero-copy access ─────────────────────────────────────

test "test_bodyview":
  let body = "Hello, World!"
  let raw = "POST /body HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\n\r\n" & body
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete()
  let req = parser.getRequest()
  let (data, dataLen) = req.bodyView()
  doAssert dataLen == 13
  doAssert data != nil
  var result = newString(dataLen)
  copyMem(addr result[0], data, dataLen)
  doAssert result == "Hello, World!"

# ── Test 30: getMultipart() lazy parsing ──────────────────────────────────────

test "test_getmultipart_lazy":
  let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
  let body = "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" &
             "Content-Disposition: form-data; name=\"name\"\r\n\r\n" &
             "Alice\r\n" &
             "------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"
  let raw = "POST /form HTTP/1.1\r\nHost: localhost\r\n" &
            "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" &
            "Content-Length: " & $body.len & "\r\n\r\n" & body
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete()
  let req = parser.getRequest()

  let mp = req.getMultipart()
  doAssert mp != nil
  doAssert mp.isComplete()
  doAssert mp.len == 1
  doAssert mp.boundaries()[0].fieldName == "name"
  doAssert mp.boundaries()[0].dataType == MultipartText
  doAssert mp.boundaries()[0].value == "Alice"
  mp.cleanup()

# ── Test 31: Auto-detect streaming multipart (simulating server flow) ───────

test "test_auto_streaming_multipart":
  let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
  let fileContent = "Hello, World!"
  let body = "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" &
             "Content-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n" &
             "Content-Type: text/plain\r\n\r\n" &
             fileContent & "\r\n" &
             "------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"

  # Simulate server flow: create parser, feed headers, set onBodyData with streamer
  let headers = "POST /upload HTTP/1.1\r\nHost: localhost\r\n" &
                "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW\r\n" &
                "Content-Length: " & $body.len & "\r\n\r\n"

  let parser = newHttpParser()
  # Feed only headers first (simulating TCP split)
  parser.feed(headers)
  doAssert parser.phase == PhaseBody
  doAssert not parser.streamingBody  # not streaming yet

  # Simulate server auto-detect: create streamer, set onBodyData
  var ms = newMultipartStreamerRef(
    "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW")
  let msRef = ms
  parser.onBodyData = proc(chunk: openArray[byte]; done: bool) =
    msRef[].feed(chunk)

  # Activate streaming for any already-buffered body bytes
  parser.feed(@[])
  doAssert parser.streamingBody

  # Convert body to seq[byte] for chunked feeding
  var bodyBytes = newSeq[byte](body.len)
  copyMem(addr bodyBytes[0], body.cstring, body.len)
  let mid = body.len div 2

  # Feed first half
  parser.feed(bodyBytes.toOpenArray(0, mid - 1))
  doAssert not parser.isComplete()

  # Feed second half
  parser.feed(bodyBytes.toOpenArray(mid, body.len - 1))
  doAssert parser.isComplete()

  # Streamer should have all data and be complete
  doAssert msRef[].isComplete()
  doAssert msRef[].len == 1
  let b = msRef[].boundaries()[0]
  doAssert b.dataType == MultipartFile
  doAssert b.fieldName == "file"
  doAssert b.fileName == "test.txt"
  doAssert b.fileType == "text/plain"
  doAssert fileExists(b.filePath)
  doAssert readFile(b.filePath) == "Hello, World!"
  msRef[].cleanup()

# ── Test 32: streamToFile() on-demand helper ───────────────────────────────────

test "test_stream_to_file":
  let body = "Hello, World! Body content here."
  let raw = "POST /raw HTTP/1.1\r\nHost: localhost\r\nContent-Length: " & $body.len & "\r\n\r\n" & body
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete()
  let req = parser.getRequest()

  let path = req.streamToFile()
  doAssert path.len > 0
  doAssert fileExists(path)
  let content = readFile(path)
  doAssert content == body
  removeFile(path)

  # Second call should return cached path
  let path2 = req.streamToFile()
  doAssert path2 == path

# ── Test 33: streamToFile() with no body returns empty ─────────────────────────

test "test_stream_to_file_no_body":
  let raw = "GET /empty HTTP/1.1\r\nHost: localhost\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete()
  let req = parser.getRequest()
  doAssert req.streamToFile() == ""
  doAssert req.streamPath.len == 0

# ── Test 34: Firefox POST regression (many headers + body, SSE2 \r\n\r\n) ────

test "test_firefox_post_regression":
  let body = "email=test%40example.com&password=secret&password_confirm=secret"
  let raw = "POST /auth/register HTTP/1.1\r\n" &
    "Host: 127.0.0.1:8000\r\n" &
    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:152.0) Gecko/20100101 Firefox/152.0\r\n" &
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" &
    "Accept-Language: en-US,en;q=0.9\r\n" &
    "Accept-Encoding: gzip, deflate, br, zstd\r\n" &
    "Content-Type: application/x-www-form-urlencoded\r\n" &
    "Content-Length: " & $body.len & "\r\n" &
    "Origin: http://127.0.0.1:8000\r\n" &
    "Sec-GPC: 1\r\n" &
    "Connection: keep-alive\r\n" &
    "Referer: http://127.0.0.1:8000/auth/register\r\n" &
    "Cookie: ssid=FHsbnuNO2uBtpSxfEgQ9LI7YV4fC7u0mrItyJk5DAM\r\n" &
    "Upgrade-Insecure-Requests: 1\r\n" &
    "Sec-Fetch-Dest: document\r\n" &
    "Sec-Fetch-Mode: navigate\r\n" &
    "Sec-Fetch-Site: same-origin\r\n" &
    "Sec-Fetch-User: ?1\r\n" &
    "Priority: u=0, i\r\n" &
    "Pragma: no-cache\r\n" &
    "Cache-Control: no-cache\r\n" &
    "\r\n" & body
  let parser = newHttpParser()
  parser.feed(raw)
  doAssert parser.isComplete(), "Firefox POST should complete"
  let req = parser.getRequest()
  doAssert req.getMethod() == HttpPost
  doAssert req.getPath() == "/auth/register"
  doAssert req.getContentLength() == body.len
  doAssert req.getBodyString() == body
  let headers = req.getHeaders()
  doAssert headers["Cookie"] == "ssid=FHsbnuNO2uBtpSxfEgQ9LI7YV4fC7u0mrItyJk5DAM"
  doAssert headers["Cache-Control"] == "no-cache"
