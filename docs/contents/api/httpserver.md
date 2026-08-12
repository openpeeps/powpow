---
title: httpserver
description: "The HTTP server and HttpResponse API: server procs, the response builder and static-file serving."
keywords: ["powpow", "api", "httpserver", "response", "http"]
---

# httpserver

Non-blocking HTTP/1.1 server combining TCP + parser; static file serving with
Range/conditional requests. Source: `src/powpow/proto/httpserver.nim`.
Guides: [server](../http/server.md), [static files](../http/static-files.md),
[requests](../http/requests.md).

## Constants

```nim
DefaultKeepAliveMs* = 5_000
MaxWsPoolSize* = 2048
DefaultChunkSize* = 1_048_576
```

## Types

```nim
OnRequestCallback* = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.}

HttpResponse* = ref object
  server*: HttpServer

HttpServer* = ref object
  handler*: OnRequestCallback
  sslCtx*: tls.SslContext
  maxBodySize*: int64
  maxStreamBodySize*: int64
  maxFileSize*: int64
  maxFieldSize*: int64
  maxConnections*: int
  maxPipelineDepth*: int
  readTimeoutMs*: int
  wsIdleTimeoutMs*: int
  timeoutSweepMs*: int
```

## Server procs

```nim
proc newHttpServer*(loop: Loop; populate: bool = true): HttpServer
proc newHttpServer*(populate: bool = true): HttpServer          # own loop
proc start*(server: HttpServer, handler: OnRequestCallback, port: Port)
proc stop*(server: HttpServer)
proc listen*(server: HttpServer, address: string, port: int)
proc listenUnix*(server: HttpServer, path: string; mode: int = 0o660)   # POSIX
proc close*(server: HttpServer)
proc populatePools*(server: HttpServer; poolSize = 256)
proc setKeepAliveTimeout*(server: HttpServer, ms: int)
proc removeSession*(server: HttpServer, conn: Connection)
proc ensureTcpServer*(server: HttpServer)
proc addConnection*(server: HttpServer, fd: SocketHandle) {.inline.}
proc getLoop*(server: HttpServer): Loop {.inline.}

# WebSocket pool integration
proc wsPoolPop*(server: HttpServer): pointer {.inline.}
proc wsPoolAdd*(server: HttpServer, ws: pointer) {.inline.}
```

## Response procs

```nim
proc status*(res: HttpResponse, code: HttpCode): HttpResponse {.inline, discardable.}
proc header*(res: HttpResponse, key, value: string): HttpResponse {.inline, discardable.}
proc close*(res: HttpResponse): HttpResponse {.inline, discardable.}
proc send*(res: HttpResponse, body: string = "")
proc send*(res: HttpResponse, body: seq[byte])
proc sendError*(res: HttpResponse, code: HttpCode, msg: string = "")
proc getConn*(res: HttpResponse): Connection {.inline.}
proc getClientIp*(res: HttpResponse): string {.inline.}
proc markSent*(res: HttpResponse) {.inline.}
```

## Static file procs

```nim
func getFileExt*(path: string): string {.inline.}
func parseRange*(rangeHeader: string; fileSize: int64): tuple[ok: bool; start, length: int64]
proc writeDisposition*(buf: ptr UncheckedArray[byte]; name: string; p: var int) {.inline.}
proc sendFile*(res: HttpResponse, path: string;
               req: HttpRequest = default(HttpRequest);
               closeConn = true, contentDisposition = true, skipRange = false)
proc streamFile*(res: HttpResponse, path: string, req: HttpRequest;
                 chunkSize = DefaultChunkSize) {.gcsafe.}
proc serveStatic*(res: HttpResponse, req: HttpRequest,
                  urlPrefix: string, fsRoot: string,
                  indexFiles: openArray[string] = ["index.html", "index.htm"]): bool
proc serveFile*(res: HttpResponse, req: HttpRequest, path: string;
                fsRoot: string = ""; contentType: string = "";
                attach: bool = false; etag: string = "";
                lastModified: string = ""; chunkSize: int64 = 0): bool

# path safety
proc resolveReal*(path: string): string
proc withinRoot*(root, path: string): bool
```

## Related

- [http](http.md) — the parser and `HttpRequest`
- [ws](ws.md) — `websocketUpgrade` integrates here
- [tls](tls.md) — `sslCtx` for HTTPS
