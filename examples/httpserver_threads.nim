## examples/httpserver.nim — Runnable multi-threaded HTTP server demo.
##
## A small but functional HTTP server showcasing powpow's multi-threaded
## HTTP module.  Spawns one event-loop thread per CPU core, all bound to
## the same port (SO_REUSEPORT).  The kernel load-balances connections.
##
## Run:
##   nim c -r --threads:on examples/httpserver.nim
##
## Test:
##   curl http://localhost:9000/
##   curl http://localhost:9000/hello
##   curl http://localhost:9000/api/echo -d 'Hello powpow!'
##   curl -X DELETE http://localhost:9000/api/items/42

import ../src/powpow
import std/[httpcore, strutils, times]

# Pass an explicit thread count, e.g. newMultiThreadHttpServer(4),
# or omit the argument to default to countProcessors().
let server = newMultiThreadHttpServer()

# ── Routes ───────────────────────────────────────────────────────────────────

server.get("/") do (req: HttpRequest, res: Response):
  res.status(Http200)
     .header("Content-Type", "text/html; charset=utf-8")
     .send("")
#      .send("""<!DOCTYPE html>
# <html>
# <head><title>powpow</title></head>
# <body>
#   <h1>⚡ powpow HTTP server</h1>
#   <p>A high-performance, non-blocking HTTP/1.1 server in Nim.</p>
#   <ul>
#     <li><a href="/hello">GET /hello</a></li>
#     <li><a href="/time">GET /time</a></li>
#     <li><a href="/api/echo">POST /api/echo</a> — echo body back</li>
#     <li><a href="/api/items/42">DELETE /api/items/42</a></li>
#   </ul>
# </body>
# </html>""")

server.get("/hello") do (req: HttpRequest, res: Response):
  let name = req.getQuery()
  var greeting = "Hello, World!"
  if name.len > 0:
    for pair in name.split('&'):
      let kv = pair.split('=')
      if kv.len == 2 and kv[0] == "name":
        greeting = "Hello, " & kv[1] & "!"
        break
  res.status(Http200)
     .header("Content-Type", "text/plain; charset=utf-8")
     .send(greeting)

server.get("/time") do (req: HttpRequest, res: Response):
  res.status(Http200)
     .header("Content-Type", "text/plain; charset=utf-8")
     .send($now())

server.post("/api/echo") do (req: HttpRequest, res: Response):
  let body = req.getBodyString()
  let contentType = req.getHeaders().getOrDefault("Content-Type",
                                                    @["application/octet-stream"].HttpHeaderValues)
  res.status(Http200)
     .header("Content-Type", contentType)
     .send(body)

server.delete("/api/items/:id") do (req: HttpRequest, res: Response):
  # Simple path extraction (no router yet — just split manually)
  let path = req.getPath()
  let parts = path.split('/')
  let id = if parts.len >= 4: parts[3] else: "?"
  res.status(Http200)
     .header("Content-Type", "application/json")
     .send("{\"deleted\": \"" & id & "\"}")

# Catch-all 404
server.notFound do (req: HttpRequest, res: Response):
  res.sendError(Http404,
    "404 Not Found: " & $req.getMethod() & " " & req.getPath())

# ── Start ────────────────────────────────────────────────────────────────────

# listen() blocks the main thread. Each worker thread runs its own
# event loop on the same port. Press Ctrl+C to stop.
server.listen("0.0.0.0", 9000)
