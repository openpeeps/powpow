---
title: Static file server
description: "serveStatic with CORS headers plus a small JSON API on the side."
keywords: ["powpow", "example", "static_server"]
---

# Static file server

Serves `examples/www/` under `/static/` using `serveStatic`, which streams files zero-copy via `sendFile` and is hardened against path traversal and symlink escapes. CORS headers are attached to every response, and a tiny JSON endpoint shows static and dynamic routes coexisting.

Source: [`examples/static_server.nim`](../../examples/static_server.nim)

```nim
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
```

## Running

```bash
nim c -r examples/static_server.nim
```

## Try it

```bash
curl -i http://localhost:9004/static/index.html
curl -H "Origin: https://example.com" -i http://localhost:9004/static/index.html
curl http://localhost:9004/api/time
```

## How it works

- `serveStatic(res, req, "/static/", WwwRoot)` maps URL prefixes to a directory tree and returns false when nothing matched (then answered with 404).
- `currentSourcePath().parentDir() / "www"` makes the www root independent of the working directory you launch from.
- Global response headers (`Access-Control-Allow-Origin`, methods) are set before routing so every reply carries them.
- Redirects are plain `Http302` responses with a `Location` header.

