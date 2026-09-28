## examples/http2server_threads.nim — Runnable multi-threaded HTTP/2 demo.
##
## One event-loop thread per CPU core, all serving h2c on the same port
## (SO_REUSEPORT). The kernel load-balances connections across workers.
##
## Run (cleartext h2c):
##   nim c --threads:on -d:release -r examples/http2server_threads.nim
##
## Test:
##   curl --http2-prior-knowledge http://localhost:9040/hello
##   h2load -n1000000 -c32 -m100 -t4 http://localhost:9040/hello

import ../src/powpow
import std/[os, strutils, times]
when not defined(windows):
  import std/cpuinfo

const Port = 9040

proc handler(req: H2Request, res: H2Response) {.gcsafe.} =
  {.gcsafe.}:
    let meth = req.meth
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
  <h1>powpow HTTP/2 server (multi-threaded)</h1>
  <p>Multiplexed streams over one TCP connection (RFC 7540).</p>
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

when not defined(windows):
  let workers =
    if paramCount() >= 1:
      try: max(1, parseInt(paramStr(1)))
      except ValueError: countProcessors()
    else:
      countProcessors()
  echo "powpow HTTP/2 server (h2c) on http://localhost:" & $Port &
    " with " & $workers & " workers"
  echo "  Press Ctrl+C to stop"
  let server = newMultiThreadH2Server(workers)
  server.start(handler, "127.0.0.1", Port)
else:
  echo "threads not supported on Windows"
  quit(1)
