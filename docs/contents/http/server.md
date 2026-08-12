---
title: HTTP server
description: "The powpow HTTP/1.1 server: handlers, the fluent response builder, configuration fields, and bring-your-own-router design."
keywords: ["powpow", "http", "server", "handler", "response"]
---

# HTTP server

`proto/httpserver.nim` is a non-blocking HTTP/1.1 server combining the TCP layer
and the [parser](parser.md). It is deliberately **router-less**: you provide one
callback and route however you like (plain `if`/`case`, or a framework such as
Supranim on top).

Runnable examples: [`examples/httpserver.nim`](../../examples/httpserver.nim),
[`examples/static_server.nim`](../../examples/static_server.nim).

## Creating a server

```nim
let server = newHttpServer(loop)        # share an existing loop
let server = newHttpServer()            # create its own loop
```

`populate: bool = true` prewarms the connection/parser/response pools by
default. `populatePools(server, poolSize = 256)` re-prewarms explicitly.

## The handler

```nim
proc handler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  case req.getMethod():
    of HttpGet:
      if req.getPath() == "/":
        res.status(Http200).header("Content-Type", "text/html; charset=utf-8")
           .send("<h1>Hello</h1>")
      else:
        res.sendError(Http404, "not found")
    else:
      res.sendError(Http405)
```

`OnRequestCallback = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.}`

The callback is `{.gcsafe.}` so it can run on multiple threads
(see [concurrency](../concurrency.md)).

## Starting / listening

```nim
server.start(handler, Port(9000))            # listen on 0.0.0.0:9000
server.listen("127.0.0.1", 9000)             # explicit address (HTTP)
server.listenUnix("/tmp/app.sock", 0o660)    # UDS, POSIX
server.stop()
server.close()
```

`getLoop(server)` returns the server's loop; `ensureTcpServer` lazily creates
the underlying `TcpServer`; `addConnection(fd)` injects an accepted fd.

## Response builder

`status`/`header`/`close` are fluent (they return `HttpResponse`):

```nim
res.status(Http200)                        # set status code
   .header("Content-Type", "application/json")
   .header("X-Frame-Options", "DENY")
   .send("""{"ok": true}""")               # send body (string or seq[byte])

res.send()                                 # empty body
res.close()                                # mark connection close
res.sendError(Http404, "custom message")   # canned error page
```

`res.getConn()` → the underlying `Connection`; `res.getClientIp()` → client IP;
`res.markSent()` marks the response sent without sending.

Responses are served with a `Date` header (RFC 7231), pipelined requests are
processed in order, and keep-alive is on by default
(`setKeepAliveTimeout(ms)`, default `DefaultKeepAliveMs` = 5000).

## Streaming a response body

`res.send` writes the buffer; for large bodies use the zero-copy file APIs or
write chunks directly:

```nim
discard res.getConn().send("partial bytes")
```

## Serving files

- `res.sendFile(path, req, ...)` — one-shot zero-copy download
- `res.streamFile(path, req, chunkSize)` — chunked streaming, keep-alive, Range
- `serveFile(res, req, path, fsRoot, ...)` — full conditional/Range semantics
- `serveStatic(res, req, urlPrefix, fsRoot, indexFiles)` — static site serving

See [static files](static-files.md) for the full matrix.

## Server configuration

`HttpServer` public fields (see [security](../security.md) for the recommended
production values):

| Field | Purpose |
|---|---|
| `handler` | the `OnRequestCallback` |
| `sslCtx` | TLS context → HTTPS (see [TLS](../net/tls.md)) |
| `maxBodySize` | max request body (0 = use `maxStreamBodySize`) |
| `maxStreamBodySize` | hard cap for streamed bodies |
| `maxFileSize` | max single uploaded file part |
| `maxFieldSize` | max single text field |
| `maxConnections` | concurrent connection cap |
| `maxPipelineDepth` | pipelined requests per connection |
| `readTimeoutMs` | slowloris / partial-request timeout |
| `wsIdleTimeoutMs` | WebSocket idle timeout |
| `timeoutSweepMs` | timeout sweep interval |

## Constants

`DefaultKeepAliveMs` = 5000, `MaxWsPoolSize` = 2048,
`DefaultChunkSize` = 1 MiB (1_048_576).

## API reference

Full signatures: [HTTP server API](../api/httpserver.md). Related:
[requests](requests.md), [static files](static-files.md),
[multipart](multipart.md), [rate limiting](rate-limiting.md).
