# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## Shows how to run HTTP and WebSocket on the same port using
## powpow's websocketUpgrade proc.
##
## Run:
##   nim c -r examples/wsupgrade.nim
##
## Test HTTP:
##   curl http://localhost:9000/
##   curl http://localhost:9000/time
##
## Test WebSocket:
##   websocat ws://localhost:9000/ws
##   npx wscat -c ws://localhost:9000/ws

import ../src/powpow
import std/[httpcore, strutils, times]

let loop = newLoop()
let server = newHttpServer(loop)

# ── HTTP Routes ──────────────────────────────────────────────────────────────

server.get("/") do (req: HttpRequest, res: Response):
  res.status(Http200)
     .header("Content-Type", "text/html; charset=utf-8")
     .send("""<!DOCTYPE html>
<html>
<head><title>powpow WebSocket</title></head>
<body>
  <h1>⚡ powpow HTTP + WebSocket server</h1>
  <p>Both HTTP and WebSocket on the same port!</p>
  <ul>
    <li><a href="/time">GET /time</a> — plain HTTP</li>
    <li>ws://localhost:9000/ws — WebSocket endpoint</li>
  </ul>
  <h2>WebSocket Test</h2>
  <div id="log" style="font-family: monospace; white-space: pre-wrap;"></div>
  <script>
    const log = document.getElementById('log');
    const ws = new WebSocket('ws://' + location.host + '/ws');
    ws.onopen = () => { log.textContent += 'Connected!\n'; ws.send('Hello from browser!'); };
    ws.onmessage = (e) => { log.textContent += '← ' + e.data + '\n'; };
    ws.onclose = () => { log.textContent += 'Disconnected.\n'; };
  </script>
</body>
</html>""")

server.get("/time") do (req: HttpRequest, res: Response):
  res.status(Http200)
     .header("Content-Type", "text/plain; charset=utf-8")
     .send($now())

# ── WebSocket upgrade route ──────────────────────────────────────────────────
#
# When a GET /ws request arrives with WebSocket upgrade headers,
# call websocketUpgrade() to take over the connection.

server.get("/ws") do (req: HttpRequest, res: Response):
  websocketUpgrade(res, req, server,
    onOpen = proc(ws: WsConnection) =
      echo "⚡ WS client connected on /ws"
      ws.sendText("Welcome to powpow WebSocket via HTTP upgrade!")
    ,
    onMessage = proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
      if kind == wsText:
        let msg = cast[string](@data)
        echo "← ws text: ", msg
        ws.sendText("echo: " & msg)
      elif kind == wsBinary:
        ws.sendBinary(data)
    ,
    onClose = proc(ws: WsConnection, code: int, reason: string) =
      echo "⚡ WS client disconnected (code=", code, ")"
    ,
    onError = proc(ws: WsConnection, err: string) =
      echo "⚠ WS error: ", err
    ,
  )

# Catch-all 404
server.notFound do (req: HttpRequest, res: Response):
  res.sendError(Http404,
    "404 Not Found: " & $req.getMethod() & " " & req.getPath())

# ── Start ────────────────────────────────────────────────────────────────────

server.listen("0.0.0.0", 9000)
echo "⚡ powpow HTTP + WS server listening on http://localhost:9000"
echo "  HTTP:       curl http://localhost:9000/"
echo "  WebSocket:  websocat ws://localhost:9000/ws"
echo "  Press Ctrl+C to stop"

loop.run()
server.close()
loop.close()
