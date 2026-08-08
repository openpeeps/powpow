## audit/request_line_strict.nim
##
## Round-2: strict request-line parsing (empty path, non-digit version, trailing
## garbage after the version) AND the SSE2 \r\n boundary bug that broke
## pipelining when a \r\n spans a 16-byte chunk boundary.

import powpow/proto/http
import std/[unittest, strutils]

suite "request line strictness":

  test "malformed request lines are rejected with 400":
    for raw in [
      "GET  HTTP/1.1\r\nHost: localhost\r\n\r\n",
      "GET / HTTP/1.x\r\nHost: localhost\r\n\r\n",
      "GET / HTTP/1.1x\r\nHost: localhost\r\n\r\n",
      "GET / HTTP/1.1garbage\r\nHost: localhost\r\n\r\n",
    ]:
      let parser = newHttpParser()
      parser.feed(raw)
      check parser.isError()
      check parser.error() == Http400

  test "trailing OWS after the version is tolerated":
    let parser = newHttpParser()
    parser.feed("GET / HTTP/1.1 \r\nHost: localhost\r\n\r\n")
    check parser.isComplete()

suite "SSE2 \\r\\n boundary bug (pipelining)":

  test "many pipelined requests parse when a \\r\\n spans a 16-byte boundary":
    # The first request's CRLF lands at index 15/16 — right across the SSE2
    # 16-byte chunk boundary. The scanner must still return the earliest CRLF.
    var raw = ""
    for i in 0 ..< 50:
      raw.add("GET /" & $i & " HTTP/1.1\r\nHost: localhost\r\n\r\n")
    let parser = newHttpParser()
    parser.feed(raw)
    check parser.isComplete()
    var count = 0
    while parser.isComplete():
      discard parser.getRequest()
      inc count
      parser.resetForNext()
      discard parser.feed(@[])
    check count == 50, "all 50 pipelined requests must parse, got " & $count

  test "double CRLF spanning a 16-byte boundary is found":
    import powpow/proto/simdscan
    var buf = newSeq[byte](64)
    # \r\n\r\n at positions 14..17 (spans the 16-byte boundary)
    buf[14] = '\r'.byte; buf[15] = '\n'.byte; buf[16] = '\r'.byte; buf[17] = '\n'.byte
    check findDoubleCRLF(cast[ptr UncheckedArray[byte]](addr buf[0]), 0, 64) == 18
