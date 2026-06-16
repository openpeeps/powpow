## examples/httpserver.nim — Runnable HTTP server demo.
##
## A small but functional HTTP server showcasing powpow's HTTP module.
##
## Run:
##   nim c -r examples/httpserver.nim
##
## Test:
##   curl http://localhost:9000/
##   curl http://localhost:9000/hello
##   curl http://localhost:9000/api/echo -d 'Hello powpow!'
##   curl -X DELETE http://localhost:9000/api/items/42

import ../src/powpow
import std/[httpcore, strutils, times]

let server = newHttpServer()

# ── Handler ──────────────────────────────────────────────────────────────────

proc handler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  {.gcsafe.}:
    let meth = req.getMethod()
    let path = req.getPath()

  if meth == HttpGet and path == "/":
    res.status(Http200)
       .header("Content-Type", "text/html; charset=utf-8")
       .send("""<!DOCTYPE html>
<html>
<head><title>powpow</title></head>
<body>
  <h1>⚡ powpow HTTP server</h1>
  <p>A high-performance, non-blocking HTTP/1.1 server in Nim.</p>
  <ul>
    <li><a href="/hello">GET /hello</a></li>
    <li><a href="/time">GET /time</a></li>
    <li><a href="/api/echo">POST /api/echo</a> — echo body back</li>
    <li><a href="/api/items/42">DELETE /api/items/42</a></li>
  </ul>
</body>
</html>""")

  elif meth == HttpGet and path == "/hello":
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

  elif meth == HttpGet and path == "/time":
    res.status(Http200)
       .header("Content-Type", "text/plain; charset=utf-8")
       .send($now())

  elif meth == HttpPost and path == "/api/echo":
    let body = req.getBodyString()
    let contentType = req.getHeaders().getOrDefault("Content-Type",
                                                      @["application/octet-stream"].HttpHeaderValues)
    res.status(Http200)
       .header("Content-Type", contentType)
       .send(body)

  elif meth == HttpDelete and path.startsWith("/api/items/"):
    # Simple path extraction (no router yet — just split manually)
    let parts = path.split('/')
    let id = if parts.len >= 4: parts[3] else: "?"
    res.status(Http200)
       .header("Content-Type", "application/json")
       .send("{\"deleted\": \"" & id & "\"}")

  else:
    res.sendError(Http404,
      "404 Not Found: " & $meth & " " & path)

# ── Start ────────────────────────────────────────────────────────────────────

echo "⚡ powpow HTTP server listening on http://localhost:9000"
echo "  Press Ctrl+C to stop"
server.start(handler, Port(9000))
