---
title: HTTP client
description: "Sync and async HTTP requests, pooling, and Unix socket usage."
keywords: ["powpow", "example", "httpclient"]
---

# HTTP client

Exercises both client flavors against a local server. The sync `HttpClient` blocks and raises `HttpError` on failure; the async variant awaits with asyncdispatch. A third snippet shows the `unixSocket` parameter for UDS origins.

Source: [`examples/httpclient.nim`](../../examples/httpclient.nim)

```nim
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
```

## Running

```bash
nim c -r examples/httpserver.nim        # target server
nim c -r examples/httpclient.nim        # then this
```

## How it works

- `newHttpClient()` / `newAsyncHttpClient()` own private event loops; `close()` releases pooled connections.
- Verb shortcuts (`get`, `post`, ...) return a response whose accessors are `getStatusCode`, `getStatusText`, `getBodyString`, `getContentLength`.
- Keep-alive connections pool per origin automatically; stale server-closed connections retry transparently once.
- UDS requests pass `unixSocket = "/tmp/powpow_http.sock"` while the URL still names the virtual host.

Full signatures in [API: httpclient](../api/httpclient.md); guide in [HTTP client](../http/client.md).

