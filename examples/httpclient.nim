## examples/httpclient.nim — HTTP client demo: sync + async + Unix sockets.
##
## Uses the powpow HttpClient (blocking) and AsyncHttpClient (await-able).
##
## Run a server first, e.g. examples/httpserver.nim (port 9000), then:
##   nim c -r examples/httpclient.nim

import ../src/powpow
import std/[asyncdispatch, strutils]

# ── Sync: blocking HttpClient ────────────────────────────────────────────────

proc demoSync() =
  let client = newHttpClient()
  echo "── sync GET http://localhost:9000/ ──"
  let res = client.get("http://localhost:9000/")
  echo "  status: " & $res.getStatusCode().int & " " & $res.getStatusText()
  let body = res.getBodyString()
  echo "  length: ", res.getContentLength()
  echo "  body:   ", body[0 ..< min(80, body.len)].replace("\n", "\\n")

  echo "── sync POST http://localhost:9000/upload ──"
  let postRes = client.post("http://localhost:9000/upload", "hello from powpow client")
  echo "  status: ", postRes.getStatusCode().int, " ", postRes.getBodyString()

  client.close()

# ── Async: await-able AsyncHttpClient ───────────────────────────────────────

proc demoAsync() {.async.} =
  echo "── async GET http://localhost:9000/time ──"
  let client = newAsyncHttpClient()
  try:
    let res = await client.get("http://localhost:9000/time")
    echo "  status: ", res.getStatusCode().int
    echo "  body:   ", res.getBodyString()
  except HttpError as e:
    echo "  error:  ", e.msg
  client.close()

# ── Unix domain socket: sync HttpClient over a UDS ──────────────────────────

proc demoUds() =
  ## Requires a server listening on a Unix socket (see examples/stream_pipe.nim
  ## or any UDS HTTP server). This just shows the API shape.
  let sockPath = "/tmp/powpow_http.sock"
  echo "── sync GET over UDS ", sockPath, " ──"
  let client = newHttpClient()
  try:
    let res = client.get("http://localhost/", [], unixSocket = sockPath)
    echo "  status: ", res.getStatusCode().int, " ", res.getBodyString()
  except HttpError as e:
    echo "  error:  ", e.msg
  client.close()

when isMainModule:
  demoSync()
  waitFor demoAsync()
  demoUds()
