## tests/test_http.nim — Tests for the HTTP parser.
##
## Tests: basic GET, POST with body, query string, headers, chunked, keep-alive.

import ../src/powpow
import std/[httpcore, strutils, unittest]

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
