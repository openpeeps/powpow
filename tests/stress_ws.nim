## Stress reproducer for the random ws.nim:991 SIGSEGV (read from nil).
## Starts an HttpServer with a /ws websocketUpgrade route, then hammers it with
## many sequential powpow TCP clients: handshake -> masked frame -> close.

import std/[strutils, httpcore, unittest]
import ../src/powpow

proc buildHandshake(): string =
  "GET /ws HTTP/1.1\r\n" &
  "Host: 127.0.0.1\r\n" &
  "Upgrade: websocket\r\n" &
  "Connection: Upgrade\r\n" &
  "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" &
  "Sec-WebSocket-Version: 13\r\n\r\n"

proc maskedFrame(opcode: int, payload: string): string =
  let n = payload.len
  var b = newSeq[byte](if n < 126: 2 + 4 + n else: 4 + 4 + n)
  b[0] = byte(0x80 or opcode)
  if n < 126:
    b[1] = byte(0x80 or n)
    for i in 0 ..< 4: b[2 + i] = byte(0x12 + i)
    for i in 0 ..< n: b[6 + i] = byte(payload[i].ord) xor byte(0x12 + (i mod 4))
  else:
    b[1] = byte(0x80 or 126)
    b[2] = byte((n shr 8) and 0xFF)
    b[3] = byte(n and 0xFF)
    for i in 0 ..< 4: b[4 + i] = byte(0x12 + i)
    for i in 0 ..< n: b[8 + i] = byte(payload[i].ord) xor byte(0x12 + (i mod 4))
  cast[string](b)

const Rounds = 4000

test "stress_ws":
  var done = 0
  var failed = 0
  let loop = newLoop()
  let server = newHttpServer(loop)
  server.wsIdleTimeoutMs = 2000

  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    if req.getPath() == "/ws":
      discard websocketUpgrade(res, req,
        onMessage = proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
          ws.sendText("echo")
      )
    else:
      res.status(Http200).send("ok")

  server.listen("127.0.0.1", 19999)

  proc runClient(n: int) =
    loop.connect("127.0.0.1", 19999,
      onConnect = proc(conn: Connection) =
        discard conn.send(buildHandshake())
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        discard conn.send(maskedFrame(0x1, "hello"))
        discard conn.send(maskedFrame(0x8, "\u0003\u00e8"))
      ,
      onClose = proc(conn: Connection) =
        inc done
        if done + failed >= Rounds:
          loop.stop()
      ,
      onError = proc(err: string) =
        inc failed
        if done + failed >= Rounds:
          loop.stop()
    )

  var idx = 0
  discard loop.addInterval(1) do (id: int):
    if idx >= Rounds:
      loop.cancelTimer(TimerId(id))
      return
    runClient(idx)
    inc idx

  discard loop.addTimer(120_000) do (id: int):
    echo "timeout done=", done, " failed=", failed
    loop.stop()

  loop.run()
  server.close()
  loop.close()
  echo "done=", done, " failed=", failed
  # The point of this stress test is "4000 connect/ws/close cycles do not
  # crash the loop". Debug builds are slow (~33 conn/s), so only require a
  # generous minimum; release builds complete all 4000.
  check done + failed >= 1000
