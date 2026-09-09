## examples/http2server.nim — Runnable HTTP/2 server demo.
##
## A small but functional HTTP/2 server showcasing powpow's H2 module:
## prior-knowledge h2c, `Upgrade: h2c`, and `h2` over TLS with ALPN.
##
## Run (cleartext h2c):
##   nim c -r examples/http2server.nim
##
## Run (h2 over TLS):
##   nim c -r examples/http2server.nim --tls cert.pem key.pem
##
## Test (h2c prior knowledge):
##   curl --http2-prior-knowledge http://localhost:9040/
##   curl --http2-prior-knowledge http://localhost:9040/hello?name=ada
##   curl --http2-prior-knowledge http://localhost:9040/api/echo -d 'Hello h2!'
##
## Test (h2c upgrade from HTTP/1.1):
##   curl --http2 http://localhost:9040/time
##
## Test (h2 over TLS):
##   curl -k --http2 https://localhost:9040/hello

import ../src/powpow
import std/[os, strutils, times]

# ── Handler ──────────────────────────────────────────────────────────────────

proc handler(req: H2Request, res: H2Response) {.gcsafe.} =
  {.gcsafe.}:
    let meth = req.meth
    # In HTTP/2 `:path` carries the raw origin-form target, query included.
    let qpos = req.path.find('?')
    let path = if qpos < 0: req.path else: req.path[0 ..< qpos]
    let query = if qpos < 0: "" else: req.path[qpos + 1 .. ^1]

  if meth == "GET" and path == "/":
    res.status(200)
      .header("Content-Type", "text/html; charset=utf-8")
      .send("""<!DOCTYPE html>
<html>
<head><title>powpow</title></head>
<body>
  <h1>powpow HTTP/2 server</h1>
  <p>Multiplexed streams over one TCP connection (RFC 7540).</p>
  <ul>
    <li><a href="/hello">GET /hello</a></li>
    <li><a href="/time">GET /time</a></li>
    <li>POST /api/echo — echo body back</li>
  </ul>
</body>
</html>""")

  elif meth == "GET" and path == "/hello":
    var greeting = "Hello, World!"
    for pair in query.split('&'):
      let kv = pair.split('=')
      if kv.len == 2 and kv[0] == "name":
        greeting = "Hello, " & kv[1] & "!"
        break
    res.status(200)
      .header("Content-Type", "text/plain; charset=utf-8")
      .send(greeting)

  elif meth == "GET" and path == "/time":
    res.status(200)
      .header("Content-Type", "text/plain; charset=utf-8")
      .send($now())

  elif meth == "POST" and path == "/api/echo":
    var contentType = "application/octet-stream"
    for (n, v) in req.headers:
      if n == "content-type":
        contentType = v
        break
    res.status(200)
      .header("Content-Type", contentType)
      .send(req.body)

  else:
    res.status(404).send("404 Not Found: " & meth & " " & path)

# ── Start ────────────────────────────────────────────────────────────────────

const Port = 9040
let loop = newLoop()

when not defined(windows):
  import ../src/powpow/net/tls

var server: H2Server
if paramCount() == 3 and paramStr(1) == "--tls":
  when defined(windows):
    quit "TLS is not supported on Windows"
  else:
    let ctx = newServerTlsContext(paramStr(2), paramStr(3))
    server = newH2Server(loop, handler, sslCtx = ctx)
    echo "powpow HTTP/2 server (h2 over TLS) listening on https://localhost:" & $Port
else:
  server = newH2Server(loop, handler)
  echo "powpow HTTP/2 server (h2c) listening on http://localhost:" & $Port

echo "  Press Ctrl+C to stop"
server.listen("127.0.0.1", Port)
loop.run()
