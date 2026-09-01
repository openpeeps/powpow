## examples/httpserver_multiport.nim — Multi-port HTTP server demo.
##
## Shows powpow's multi-port support: a single HttpServer (one Loop, one
## handler) bound to several ports. All ports share the same handler,
## address ("0.0.0.0") and TLS context — only the port differs.
##
## Two equivalent ways are demonstrated:
##   1. `start` with varargs ports — `server.start(handler, Port(9000), Port(9001))`
##   2. Additive `listen` before `loop.run()` — call `listen` repeatedly
##
## Run:
##   nim c -r examples/httpserver_multiport.nim
##   # or with clue:
##   clue build examples/httpserver_multiport.nim && ./httpserver_multiport
##
## Test:
##   curl http://localhost:9000/
##   curl http://localhost:9001/
##   curl http://localhost:9000/hello?name=Ada  # works on either port
##   curl http://localhost:9001/time

import ../src/powpow
import std/[httpcore, strutils, times]

let server = newHttpServer()

proc handler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  let meth = req.getMethod()
  let path = req.getPath()
  case meth
  of HttpGet:
    if path == "/":
      res.status(Http200)
        .header("Content-Type", "text/html; charset=utf-8")
        .send("""<!DOCTYPE html>
<html>
<head><title>powpow — multi-port</title></head>
<body>
  <h1>💥 powpow multi-port demo</h1>
  <p>Same handler, two ports (9000 and 9001), one Loop.</p>
  <ul>
    <li><a href="/hello">GET /hello?name=...</a></li>
    <li><a href="/time">GET /time</a></li>
  </ul>
</body>
</html>""")
    elif path == "/hello":
      var greeting = "Hello, World!"
      let qs = req.getQuery()
      if qs.len > 0:
        for pair in qs.split('&'):
          let kv = pair.split('=')
          if kv.len == 2 and kv[0] == "name":
            greeting = "Hello, " & kv[1] & "!"
            break
      res.status(Http200)
        .header("Content-Type", "text/plain; charset=utf-8")
        .send(greeting)
    elif path == "/time":
      res.status(Http200)
        .header("Content-Type", "text/plain; charset=utf-8")
        .send($now())
    else:
      res.sendError(Http404, "404 Not Found: " & $meth & " " & path)
  else:
    res.sendError(Http404, "404 Not Found: " & $meth & " " & path)

# ── Option A: varargs `start` (recommended) ─────────────────────────────────
echo "💥 powpow HTTP server listening on http://localhost:9000 and http://localhost:9001"
echo "  Press Ctrl+C to stop"
server.start(handler, Port(9000), Port(9001))

# ── Option B: additive `listen` + manual loop ────────────────────────────────
# Use this when you need to interleave other setup (signals, timers) before
# the loop runs, or when the address is not 0.0.0.0:
#
#   import powpow/proto/httpserver
#   let loop = newLoop()
#   let server = newHttpServer(loop)
#   server.handler = handler
#   server.listen("127.0.0.1", 9000)
#   server.listen("127.0.0.1", 9001)
#   # or: server.listen("127.0.0.1", 9002) for a third port
#   echo "Listening on 9000/9001/9002"
#   loop.run()
