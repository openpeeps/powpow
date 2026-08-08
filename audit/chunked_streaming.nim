## audit/04_chunked_streaming.nim
##
## P1 — Chunked request bodies streamed via onBodyData never complete and the
## raw chunk framing is forwarded instead of decoded data. Docs promise decoded
## data and a final `done=true`.
##
## Pre-fix: phase stays PhaseBody forever, done never fires, callback sees the
## raw framing bytes ("5\r\nhello\r\n0\r\n\r\n" = 15 bytes).
## Post-fix: parser reaches PhaseComplete, done=true, callback sees "hello".

import powpow/proto/http
import std/[unittest, strutils, httpcore]

suite "chunked streaming body completes with decoded data":

  test "streamed chunked body reaches PhaseComplete with done=true":
    var received: seq[byte] = @[]
    var doneSeen = false
    let parser = newHttpParser()
    parser.onBodyData = proc(data: openArray[byte]; done: bool) {.closure.} =
      for b in data: received.add(b)
      if done: doneSeen = true

    let headers = "POST /x HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
    parser.feed(headers)
    parser.feed("5\r\nhello\r\n0\r\n\r\n")

    check parser.isComplete()
    check doneSeen
    check cast[string](received) == "hello"

  test "streamed chunked body with two chunks + empty feeds":
    var received: seq[byte] = @[]
    var doneSeen = false
    let parser = newHttpParser()
    parser.onBodyData = proc(data: openArray[byte]; done: bool) {.closure.} =
      for b in data: received.add(b)
      if done: doneSeen = true

    parser.feed("POST /x HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n")
    parser.feed("5\r\nhello\r\n")
    parser.feed("6\r\n world\r\n")
    parser.feed("0\r\n\r\n")
    parser.feed(@[])

    check parser.isComplete()
    check doneSeen
    check cast[string](received) == "hello world"

  test "streamed chunked body respects maxBodySize":
    var streamed = 0
    let parser = newHttpParser()
    parser.maxBodySize = 100
    parser.onBodyData = proc(data: openArray[byte]; done: bool) {.closure.} =
      streamed += data.len
    parser.feed("POST /x HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n")
    parser.feed("FF\r\n")   # valid chunk size of 255 > maxBodySize=100
    check parser.isError()
    check parser.error() == Http413
