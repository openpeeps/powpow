---
title: HTTP parser
description: "The incremental zero-copy HTTP/1.1 request parser: feeding bytes, parse phases, streaming bodies and limits."
keywords: ["powpow", "http", "parser", "http/1.1", "streaming"]
---

# HTTP parser

`proto/http.nim` is an incremental, zero-copy HTTP/1.1 request parser. It
materializes strings lazily from byte offsets — nothing is copied until you ask
for it — and it drives streaming bodies, chunked transfer encoding and
multipart.

Most users never touch the parser directly: the HTTP server feeds it for you and
hands you an `HttpRequest` (see [requests](requests.md)). This page is for
understanding it, or for using it standalone.

## Creating a parser

```nim
var p = newHttpParser(initialBufSize = 4096)
```

Public parser fields: `buf`, `bufLen`, `maxBodySize`, `maxStreamBodySize`,
`headerEnd`, `contentLength`, `connectionClose`, `expectContinue`,
`onBodyData` (streaming callback), `methodCache`, `phase`.

## Feeding bytes

```nim
let phase = p.feed(data)          # openArray[byte] or string
```

The parser is incremental: feed as many or as few bytes as arrive. It tracks a
`ParsePhase`: `PhaseRequestLine`, `PhaseHeaders`, `PhaseBody`,
`PhaseComplete`, `PhaseError`.

```nim
p.isComplete()          # reached PhaseComplete
p.isError()             # reached PhaseError
p.error()               # the HttpCode that caused the error
p.phase()               # current phase
p.setError(Http400)     # force an error state (rejects the request)
```

`reset` clears the parser; `resetForNext` keeps reusable state for the next
request on a keep-alive connection.

## Zero-copy request fields

Before the request is complete you can peek:

```nim
p.peekMethod()            # HttpMethod
p.peekPath()              # lent string
p.peekContentType()       # lent string
```

Once complete, materialize a request object:

```nim
let req = p.getRequest()      # HttpRequest — see requests.md
```

`getRemainingData(p)` returns bytes beyond the current request (pipelining).

## Streaming bodies

`p.onBodyData = proc(data: openArray[byte]; done: bool) {.closure.}` is invoked
as body bytes are parsed; `done` signals the final chunk. Set it **before**
feeding body bytes.

```nim
p.onBodyData = proc(data: openArray[byte]; done: bool) =
  write(f, data)          # stream to disk without buffering the whole body
```

## Limits

Constants enforced by the parser/server:

| Constant | Value |
|---|---|
| `MaxHeaderSize` | 8192 |
| `MaxRequestLine` | 8192 |
| `MaxHeaders` | 100 |
| `DefaultBodyBuf` | 65536 |
| `MaxStreamBodySize` | 512 MB |

See [security](../security.md) for how these protect against DoS.

## Body streaming on requests

For fully parsed requests, the `BodyStream` API in
[requests](requests.md) is the higher-level way to consume bodies in chunks.

## API reference

Full signatures: [HTTP parser API](../api/http.md). Related:
[requests](requests.md), [server](server.md).
