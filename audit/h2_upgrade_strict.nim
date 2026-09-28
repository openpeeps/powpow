## audit/h2_upgrade_strict.nim
##
## H2 h2c upgrade-request validation (RFC 7540 §3.2).
## Malformed HTTP2-Settings, hostile embedded SETTINGS, bodies on the
## upgrade request, and oversized sniff input must all terminate safely
## (400/426/close) — never dispatch, never hang, never crash the loop.
## A valid upgrade must 101 and dispatch stream 1.
##
## Red: handler runs on hostile input, connection hangs, or loop crashes.
## Green: exact terminal behavior below.

import powpow
import powpow/proto/[http2conn]
import std/[strutils, unittest]

var upHandlerRan = false

proc upHandler(req: H2Request, res: H2Response) {.gcsafe.} =
  {.gcsafe.}:
    upHandlerRan = true
    res.send("upgraded:" & req.path)

proc upRequest(port: int, payload: string, waitMs = 500,
               checkClosed: bool = false): tuple[resp: string, closed: bool,
                                                 handlerRan: bool] =
  ## Send a raw H1 upgrade-shaped request, collect bytes for waitMs.
  let loop = newLoop()
  let srv = newH2Server(loop, upHandler)
  srv.listen("127.0.0.1", port)
  upHandlerRan = false
  var resp = ""
  var closed = false
  loop.connect("127.0.0.1", port,
    onConnect = proc(conn: Connection) =
      discard conn.send(payload)
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      var s = newString(data.len)
      copyMem(addr s[0], unsafeAddr data[0], data.len)
      resp &= s
    ,
    onClose = proc(conn: Connection) =
      closed = true
    ,
  )
  discard loop.addTimer(waitMs) do (id: int):
    srv.close()
    loop.stop()
  loop.run()
  loop.close()
  (resp, closed, upHandlerRan)

const UpBase = "GET /up HTTP/1.1\r\nHost: x\r\n" &
  "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n"

suite "h2c upgrade validation":

  test "garbage HTTP2-Settings closes, no dispatch":
    let r = upRequest(29230, UpBase & "HTTP2-Settings: !!!not-base64!!!\r\n\r\n")
    check r.closed
    check "101" notin r.resp
    check not r.handlerRan

  test "settings length not multiple of 6 closes, no dispatch":
    # "AAAAAAA" decodes to 5 bytes: framing error, must not apply.
    let r = upRequest(29231, UpBase & "HTTP2-Settings: AAAAAAA\r\n\r\n")
    check r.closed
    check "101" notin r.resp
    check not r.handlerRan

  test "hostile embedded INITIAL_WINDOW_SIZE ends conn, no dispatch":
    # id=4, value=0x80000000 (> 2^31-1): must be rejected, never applied.
    let r = upRequest(29232, UpBase & "HTTP2-Settings: AASAAAAA\r\n\r\n")
    check r.closed
    check not r.handlerRan

  test "upgrade with Content-Length is 400, no dispatch":
    let r = upRequest(29233, UpBase &
      "HTTP2-Settings: AAQAAAQA\r\nContent-Length: 5\r\n\r\nhello")
    check "400" in r.resp
    check not r.handlerRan

  test "10KB upgrade headers hit the sniff cap, no dispatch":
    var big = UpBase & "HTTP2-Settings: AAQAAAQA\r\n"
    big &= "X-Pad: " & repeat('p', 10 * 1024) & "\r\n\r\n"
    let r = upRequest(29234, big)
    check r.closed
    check "101" notin r.resp
    check not r.handlerRan

  test "valid upgrade 101s and dispatches stream 1":
    let r = upRequest(29235, UpBase & "HTTP2-Settings: AAQAAAQA\r\n\r\n")
    check "101 Switching Protocols" in r.resp
    check r.handlerRan

  test "Transfer-Encoding on upgrade fails closed at dispatch":
    # The 101 is already staged before dispatch, so it still goes out —
    # but splitRequestHeaders refuses connection-specific fields and the
    # stream dies with PROTOCOL_ERROR instead of reaching the handler.
    # Fail-closed: correct, pinned.
    let r = upRequest(29236, UpBase &
      "HTTP2-Settings: AAQAAAQA\r\nTransfer-Encoding: chunked\r\n\r\n")
    check "101 Switching Protocols" in r.resp
    check not r.handlerRan
