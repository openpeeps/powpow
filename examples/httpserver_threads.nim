## examples/httpserver_threads.nim — Runnable multi-threaded HTTP server demo.
##
## A small but functional HTTP server showcasing powpow's multi-threaded
## HTTP module.  Spawns one event-loop thread per CPU core, all bound to
## the same port (SO_REUSEPORT).  The kernel load-balances connections.
##
## Run:
##   clue build examples/httpserver_threads.nim --out:/tmp/httpserver_threads
##
## Test:
##   curl http://localhost:9000/
##   curl http://localhost:9000/hello
##   curl http://localhost:9000/api/echo -d 'Hello powpow!'
##   curl -X DELETE http://localhost:9000/api/items/42

import ../src/powpow
import std/httpcore except HttpMethod
import std/[strutils, times]
when not defined(windows):
  import std/cpuinfo

# Multi-threaded server (POSIX only; multithread.nim is guarded with
# `when not defined(windows)`). On Windows fall back to the single-threaded
# HttpServer so the example still compiles.
when not defined(windows):
  let server = newHttpServer(countProcessors())
else:
  let server = newHttpServer()

# ── Handler ──────────────────────────────────────────────────────────────────

proc handler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  let meth = req.getMethod()
  let path = req.getPath()

  if meth == HttpGet and path == "/":
    res.status(Http200)
       .header("Content-Type", "text/html; charset=utf-8")
       .send("""<!DOCTYPE html>
<html>
<head><title>powpow</title></head>
<body>
  <h1>💥 powpow HTTP server</h1>
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
      # Single-pass scan for the first name=<value> pair: no seq[string]
      # splits. Matches split('&')/split('=') semantics exactly (first match
      # wins, kv.len == 2 required so values containing '=' are skipped,
      # empty values kept).
      const needle = "name="
      var i = 0
      while i < name.len:
        var j = i
        while j < name.len and name[j] != '&': inc j
        if j - i >= needle.len and name[i] == 'n':
          var k = 0
          while k < needle.len and i + k < j and name[i + k] == needle[k]: inc k
          if k == needle.len:
            var hasEq = false
            for t in (i + needle.len) ..< j:
              if name[t] == '=':
                hasEq = true
                break
            if not hasEq:
              let vlen = j - (i + needle.len)
              var val = newString(vlen)
              if vlen > 0:
                copyMem(addr val[0], unsafeAddr name[i + needle.len], vlen)
              greeting = "Hello, " & val & "!"
              break
        i = j + 1
    res.status(Http200)
       .header("Content-Type", "text/plain; charset=utf-8")
       .send(greeting)

  elif meth == HttpGet and path == "/time":
    res.status(Http200)
       .header("Content-Type", "text/plain; charset=utf-8")
       .send($now())

  elif meth == HttpPost and path == "/api/echo":
    # No header-table cost here: peekContentType() is a cached lent view of the
    # raw header bytes (no per-header strings, no table insert). $ct copies only
    # this one value so the response header owns its bytes instead of aliasing
    # the pooled parser buffer. Duplicate Content-Type headers resolve to the
    # parser's canonical last-wins value, the same value the framework itself
    # uses for streaming decisions.
    let ct = req.parser.peekContentType()
    let contentType = if ct.len > 0: $ct else: "application/octet-stream"
    res.status(Http200)
       .header("Content-Type", contentType)
       # getBody() copies once into the pooled request buffer and send() borrows
       # it; getBodyString() would copy a second time.
       .send(req.getBody())

  elif meth == HttpDelete and path.startsWith("/api/items/"):
    # Index scan for the id segment: one substring copy instead of a
    # seq[string] split. startsWith guarantees path.len > prefixLen.
    const prefixLen = len("/api/items/")
    var e = prefixLen
    while e < path.len and path[e] != '/': inc e
    let id = path[prefixLen ..< e]
    res.status(Http200)
       .header("Content-Type", "application/json")
       .send("{\"deleted\": \"" & id & "\"}")

  else:
    res.sendError(Http404,
      "404 Not Found: " & $meth & " " & path)

# ── Start ────────────────────────────────────────────────────────────────────

# start() blocks the main thread. Each worker thread runs its own
# event loop on the same port. Press Ctrl+C to stop.
server.start(handler, "0.0.0.0", Port(9000))
