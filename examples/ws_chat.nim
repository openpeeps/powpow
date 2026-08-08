## examples/ws_chat.nim — Multi-client WebSocket chat with broadcast.
##
## Serves a chat page at http://localhost:9006/ and a WebSocket endpoint at
## ws://localhost:9006/ws. Every text frame is broadcast to all connected
## clients (except the sender); binary frames are echoed. Open the page in
## several browser tabs and chat with yourself.
##
## Run:
##   nim c -r examples/ws_chat.nim
##
## Test:
##   open http://localhost:9006 in two browser tabs
##   # or from the terminal:
##   websocat ws://localhost:9006/ws

import ../src/powpow
import std/[httpcore, strutils, sequtils, os]

const ChatPort = 9006

var clients: seq[WsConnection]

proc broadcast(fromWs: WsConnection, text: string) =
  for c in clients:
    if c != fromWs:
      c.sendText(text)

let server = newHttpServer()
let html = readFile(currentSourcePath().parentDir() / "ws_chat.html")

server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  {.cast(gcsafe).}:
    let path = req.getPath()

    if path == "/":
      res.status(Http200)
        .header("Content-Type", "text/html; charset=utf-8")
        .send(html)
    elif path == "/ws":
      websocketUpgrade(res, req, server,
        onOpen = proc(ws: WsConnection) =
          clients.add(ws)
          echo "⚡ ws client joined (total=", clients.len, ")"
          broadcast(ws, "* a new client joined (total=" & $clients.len & ")")
        ,
        onMessage = proc(ws: WsConnection, kind: WsFrameKind,
                         data: openArray[byte]) =
          if kind == wsText:
            broadcast(ws, $cast[string](@data))
          else:
            discard  # ignore binary in this demo (or echo: ws.sendBinary(data))
        ,
        onClose = proc(ws: WsConnection, code: int, reason: string) =
          clients.keepItIf(it != ws)
          echo "⚡ ws client left (code=", code, ", total=", clients.len, ")"
          broadcast(ws, "* a client left (total=" & $clients.len & ")")
        ,
        onError = proc(ws: WsConnection, err: string) =
          echo "⚠ ws error: ", err
        ,
      )
    else:
      res.sendError(Http404, "404 Not Found: " & path)

echo "⚡ WebSocket chat on http://localhost:" & $ChatPort
echo "  Open http://localhost:" & $ChatPort & " in two browser tabs"
echo "  Press Ctrl+C to stop"
server.start(server.handler, Port(ChatPort))
