## examples/static_server.nim — Static site server with CORS.
##
## Serves a small static site from examples/www/ via `serveStatic` (zero-copy
## `sendFile` behind the scenes, path-traversal and symlink-escape safe), adds
## CORS headers to every response, and mixes in a tiny JSON API endpoint.
##
## Run:
##   nim c -r examples/static_server.nim
##
## Test:
##   curl http://localhost:9004/static/index.html
##   curl http://localhost:9004/static/style.css
##   curl -H "Origin: https://example.com" -i http://localhost:9004/static/index.html
##   curl http://localhost:9004/api/time

import ../src/powpow
import std/[httpcore, strutils, times, os]

const StaticPort = 9004
const WwwRoot = currentSourcePath().parentDir() / "www"   # examples/www, CWD-independent

let server = newHttpServer()

proc handler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  {.gcsafe.}:
    let meth = req.getMethod()
    let path = req.getPath()

    # Allow any origin — this is a demo.
    res.header("Access-Control-Allow-Origin", "*")
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    if meth == HttpGet:
      if path.startsWith("/static/"):
        if not serveStatic(res, req, "/static/", WwwRoot):
          res.sendError(Http404, "404 Not Found: " & path)
      elif path == "/static":
        res.status(Http302)
          .header("Location", "/static/")
          .send("")
      elif path == "/api/time":
        res.status(Http200)
          .header("Content-Type", "application/json")
          .send("{\"time\": \"" & $now() & "\"}")
      elif path == "/":
        res.status(Http302)
          .header("Location", "/static/index.html")
          .send("")
      else:
        res.sendError(Http404, "404 Not Found: " & $meth & " " & path)
    else:
      res.sendError(Http404, "404 Not Found: " & $meth & " " & path)

echo "⚡ static server listening on http://localhost:" & $StaticPort
echo "  Serving examples/www/ at http://localhost:" & $StaticPort & "/static/"
echo "  Press Ctrl+C to stop"
server.start(handler, Port(StaticPort))
