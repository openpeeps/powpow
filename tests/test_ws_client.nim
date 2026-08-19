## WebSocket client tests: connectWs / upgradeToWs against a real powpow
## WsServer, plus the handshake-rejection path against a plain HttpServer.

import std/[httpcore, unittest]
import ../src/powpow

test "ws_client_echo_roundtrip":
  ## Text + binary echo, then a client-initiated close that the server parses.
  var echoText = ""
  var echoBin = newSeq[byte](0)
  var serverOpened = 0
  var serverClosed = 0
  var serverCloseCode = -1
  var clientOpened = 0
  let loop = newLoop()
  let server = newWsServer(loop)
  server.onOpen do (ws: WsConnection):
    inc serverOpened
  server.onMessage do (ws: WsConnection, kind: WsFrameKind, data: openArray[byte]):
    case kind
    of wsText:
      ws.sendText(cast[string](@data))
    of wsBinary:
      ws.sendBinary(data)
    else:
      discard
  server.onClose do (ws: WsConnection, code: int, reason: string):
    serverCloseCode = code
    inc serverClosed
    loop.stop()
  server.listen("127.0.0.1", 19994)

  discard loop.addTimer(10) do (id: int):
    let ws = connectWs(loop, "127.0.0.1", 19994, "/",
      onOpen = proc(ws: WsConnection) =
        inc clientOpened
        ws.sendText("hello")
        ws.sendBinary([1.byte, 2, 3])
      ,
      onMessage = proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
        case kind
        of wsText:
          echoText = cast[string](@data)
        of wsBinary:
          echoBin = @data
        else:
          discard
        if echoText.len > 0 and echoBin.len > 0:
          ws.closeWs(1000, "done")
      ,
      onClose = proc(ws: WsConnection, code: int, reason: string) =
        discard
      ,
      onError = proc(ws: WsConnection, err: string) =
        loop.stop()
    )
    check ws != nil

  discard loop.addTimer(15_000) do (id: int):
    loop.stop()

  loop.run()
  server.close()
  loop.close()

  check clientOpened == 1
  check serverOpened == 1
  check echoText == "hello"
  check echoBin == @[1.byte, 2, 3]
  check serverClosed == 1
  check serverCloseCode == 1000

test "ws_client_server_initiated_close":
  ## The server closes; the client must observe the close frame and its code.
  var clientClosed = 0
  var clientCloseCode = -1
  var opened = 0
  let loop = newLoop()
  let server = newWsServer(loop)
  server.onMessage do (ws: WsConnection, kind: WsFrameKind, data: openArray[byte]):
    ws.closeWs(1000, "bye")
  server.listen("127.0.0.1", 19993)

  discard loop.addTimer(10) do (id: int):
    discard connectWs(loop, "127.0.0.1", 19993, "/",
      onOpen = proc(ws: WsConnection) =
        inc opened
        ws.sendText("hi")
      ,
      onMessage = proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
        discard
      ,
      onClose = proc(ws: WsConnection, code: int, reason: string) =
        clientCloseCode = code
        inc clientClosed
        loop.stop()
      ,
      onError = proc(ws: WsConnection, err: string) =
        loop.stop()
    )

  discard loop.addTimer(15_000) do (id: int):
    loop.stop()

  loop.run()
  server.close()
  loop.close()

  check opened == 1
  check clientClosed == 1
  check clientCloseCode == 1000

test "ws_client_upgrade_existing_conn":
  ## upgradeToWs over a raw loop.connect, echo round-trip, then client close.
  var got = ""
  var serverClosed = 0
  var opened = 0
  let loop = newLoop()
  let server = newWsServer(loop)
  server.onMessage do (ws: WsConnection, kind: WsFrameKind, data: openArray[byte]):
    ws.sendText("pong")
  server.onClose do (ws: WsConnection, code: int, reason: string):
    inc serverClosed
    loop.stop()
  server.listen("127.0.0.1", 19992)

  discard loop.addTimer(10) do (id: int):
    loop.connect("127.0.0.1", 19992,
      onConnect = proc(conn: Connection) =
        let ws = upgradeToWs(conn, "/", "127.0.0.1",
          onOpen = proc(ws: WsConnection) =
            inc opened
            ws.sendText("hi")
          ,
          onMessage = proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
            got = cast[string](@data)
            ws.closeWs(1000)
          ,
          onClose = proc(ws: WsConnection, code: int, reason: string) =
            discard
          ,
          onError = proc(ws: WsConnection, err: string) =
            loop.stop()
        )
        check ws != nil
      ,
      onData = proc(conn: Connection, data: openArray[byte]) = discard,
      onClose = proc(conn: Connection) = discard
    )

  discard loop.addTimer(15_000) do (id: int):
    loop.stop()

  loop.run()
  server.close()
  loop.close()

  check opened == 1
  check got == "pong"
  check serverClosed == 1

test "ws_client_handshake_reject":
  var errMsg = ""
  let loop = newLoop()
  let server = newHttpServer(loop)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http404).send("nope")
  server.listen("127.0.0.1", 19991)

  discard loop.addTimer(10) do (id: int):
    let ws = connectWs(loop, "127.0.0.1", 19991, "/",
      onError = proc(ws: WsConnection, err: string) =
        errMsg = err
        loop.stop()
    )
    check ws != nil

  discard loop.addTimer(15_000) do (id: int):
    loop.stop()

  loop.run()
  server.close()
  loop.close()

  check errMsg.len > 0
