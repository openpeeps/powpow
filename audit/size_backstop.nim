## audit/size_backstop.nim
##
## Round-2: the configurable hard cap `maxStreamBodySize` lets an operator lower
## the 512 MB backstop when `maxBodySize == 0`.

import powpow/proto/http
import std/[unittest, httpcore]

suite "configurable stream-size backstop":

  test "maxStreamBodySize caps a chunked body when maxBodySize == 0":
    let parser = newHttpParser()
    parser.maxStreamBodySize = 100
    parser.feed("POST /x HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n")
    parser.feed("100\r\n")   # 256-byte chunk > 100
    check parser.isError()
    check parser.error() == Http413

  test "maxBodySize takes precedence over maxStreamBodySize":
    let parser = newHttpParser()
    parser.maxBodySize = 50
    parser.maxStreamBodySize = 10000
    parser.feed("POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 200\r\n\r\n")
    check parser.isError()
    check parser.error() == Http413
