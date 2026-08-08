## examples/uds_server.nim — HTTP over a Unix domain socket (UDS).
##
## Serves HTTP on a Unix socket instead of TCP — ideal for ultra-low-latency
## local IPC between microservices on the same machine (no loopback TCP stack).
##
## Run:
##   nim c -r examples/uds_server.nim
##
## Test:
##   curl --unix-socket /tmp/powpow.sock http://localhost/hello
##
## (curl on macOS/Linux supports --unix-socket.)

when not defined(windows):
  import ../src/powpow
  import std/[httpcore, strutils, os]

  const SockPath = "/tmp/powpow.sock"

  # Remove a stale socket from a previous run.
  if fileExists(SockPath):
    removeFile(SockPath)

  let loop = newLoop()
  let server = newHttpServer(loop)

  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      let path = req.getPath()
      if path == "/hello":
        res.status(Http200)
          .header("Content-Type", "text/plain; charset=utf-8")
          .send("hello over a unix socket!")
      elif path == "/echo":
        let body = req.getBodyString()
        res.status(Http200)
          .header("Content-Type", "text/plain; charset=utf-8")
          .send("echo: " & body)
      else:
        res.sendError(Http404, "404 Not Found: " & path)

  server.listenUnix(SockPath)
  echo "⚡ HTTP server listening on unix socket: ", SockPath
  echo "  Test with:  curl --unix-socket ", SockPath, " http://localhost/hello"
  echo "  Press Ctrl+C to stop"
  loop.run()
