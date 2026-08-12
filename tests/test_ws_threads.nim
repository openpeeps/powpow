## Tests the cross-thread WebSocket send fix: a background thread calling
## ws.sendText while the loop runs must not race the loop's connection state
## and must deliver the frame. This mirrors booyaka's file-watcher thread.

import std/[httpcore, strutils, unittest]
import ../src/powpow
when defined(threads):
  import std/threads

proc buildHandshake(): string =
  "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" &
  "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"

when defined(threads):
  var gWs: ptr WsConnection

  proc senderThread(arg: pointer) {.thread.} =
    sleep(20)
    let ws = cast[ptr WsConnection](arg)[]
    discard ws.sendText("from-thread")
    # signal completion via postToLoop so the loop thread observes it
    if ws.conn != nil:
      ws.conn.loop.postToLoop(proc() =
        if ws.conn != nil:
          ws.conn.loop.stop())

test "ws_cross_thread_send":
  var received: seq[byte] = @[]
  let loop = newLoop()
  let server = newHttpServer(loop)
  var wsHolder: WsConnection

  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    if req.getPath() == "/ws":
      discard websocketUpgrade(res, req,
        onOpen = proc(ws: WsConnection) =
          wsHolder = ws
      )
    else:
      res.status(Http200).send("ok")
  server.listen("127.0.0.1", 19997)

  when defined(threads):
    discard loop.addTimer(10) do (id: int):
      # open a client so the upgrade completes
      loop.connect("127.0.0.1", 19997,
        onConnect = proc(conn: Connection) =
          discard conn.send(buildHandshake())
        ,
        onData = proc(conn: Connection, data: openArray[byte]) =
          received.add(data)
          if cast[string](received).contains("from-thread"):
            conn.close()
        ,
        onClose = proc(conn: Connection) =
          discard
      )
    discard loop.addTimer(100) do (id: int):
      # the upgrade should be complete; spawn the sender thread
      if wsHolder != nil:
        var t: Thread[ptr WsConnection]
        createThread(t, senderThread, cast[ptr WsConnection](addr wsHolder))
      else:
        loop.stop()
    discard loop.addTimer(30_000) do (id: int):
      loop.stop()
  else:
    discard loop.addTimer(10) do (id: int):
      loop.stop()

  loop.run()
  server.close()
  loop.close()

  when defined(threads):
    check cast[string](received).contains("from-thread")
  check true
