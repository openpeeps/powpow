## examples/wsclient.nim — WebSocket client demo using powpow's connectWs.
##
## Connects to examples/wsserver.nim (port 9001), sends a text message and
## a ping, then echoes back whatever the server sends until it closes.
##
## Run (after starting examples/wsserver.nim):
##   nim c -r examples/wsclient.nim
##
## The client works against any RFC 6455 server, e.g.:
##   websocat -E ws://localhost:9001

import ../src/powpow
import std/strutils

const Host = "127.0.0.1"
const Port = 9001

let loop = newLoop()

discard connectWs(loop, Host, Port, "/",
  onOpen = proc(ws: WsConnection) =
    echo "⚡ connected to ws://", Host, ":", Port
    ws.sendText("Hello from powpow WS client!")
    ws.sendPing()
  ,
  onMessage = proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
    let msg = cast[string](@data)
    echo "← ", kind, ": ", msg
    if msg.startsWith("echo"):
      ws.closeWs(1000, "bye")
  ,
  onClose = proc(ws: WsConnection, code: int, reason: string) =
    echo "⚡ closed (code=", code, ", reason=\"", reason, "\")"
    loop.stop()
  ,
  onError = proc(ws: WsConnection, err: string) =
    echo "⚠ error: ", err
    loop.stop()
)

# Safety timeout: exit after 30 seconds if still connected.
discard loop.addTimer(30_000) do (id: int):
  loop.stop()

loop.run()
