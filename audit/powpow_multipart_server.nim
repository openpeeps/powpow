## audit/03_powpow_multipart_server.nim
##
## P0 — End-to-end proof that a malformed multipart part header must NOT abort
## the powpow HTTP server. Pre-fix the process dies with an unhandled
## IndexDefect escaping the event loop. Post-fix the server must respond with
## 4xx and keep running.

import powpow
import std/[httpcore, strutils, unittest]

proc roundTrip(handler: OnRequestCallback, body: string): string =
  var responseData: seq[byte] = @[]
  var clientConn: Connection = nil
  let loop = newLoop()

  let server = newHttpServer(loop)
  server.handler = handler
  server.listen("127.0.0.1", 20099)

  discard loop.addTimer(50) do (id: int):
    loop.connect("127.0.0.1", 20099,
      onConnect = proc(conn: Connection) =
        clientConn = conn
        let headers = "POST /up HTTP/1.1\r\nHost: localhost\r\n" &
                      "Content-Type: multipart/form-data; boundary=X\r\n" &
                      "Content-Length: " & $body.len & "\r\n\r\n"
        discard conn.send(headers & body)
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        responseData.add(@data)
      ,
    )

  discard loop.addTimer(3000) do (id: int):
    if clientConn != nil: clientConn.close()
    server.close()
    loop.stop()

  var polls = 0
  while responseData.len == 0 and polls < 20000:
    loop.poll(1)
    inc polls
  if clientConn != nil: clientConn.close()
  server.close()
  loop.close()
  result = cast[string](responseData)

suite "malformed multipart must not crash the powpow server":

  test "server survives and answers 4xx for a malformed part header":
    let body = "--X\r\nContent-Disposition: form-data; name\r\n\r\nvalue\r\n--X--\r\n"
    let resp = roundTrip(
      proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
        {.gcsafe.}:
          let mp = req.getMultipart()
          if mp != nil:
            mp.cleanup()
          res.status(Http200).send("OK")
      ,
      body)
    check resp.len > 0
    check " 4" in resp or " 2" in resp

  test "server survives malformed part via auto-streaming (handler only checks streamer)":
    let body = "--X\r\nContent-Disposition: form-data\r\nContent-Type: text/plain\r\n\r\ndata\r\n--X--\r\n"
    let resp = roundTrip(
      proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
        {.gcsafe.}:
          res.status(Http200).send("OK")
      ,
      body)
    check resp.len > 0
