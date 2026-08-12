---
title: Requests
description: "The HttpRequest API: request line, headers, buffered and streaming bodies, and multipart access."
keywords: ["powpow", "http", "request", "body", "streaming"]
---

# Requests

Inside your handler you receive an `HttpRequest` (`req`). It is a lazy, parsed
view of the HTTP request: accessors materialize strings on demand, and the body
is available either fully-buffered or as a stream.

See also [parser](parser.md) for how requests are produced, and
[server](server.md) for the handler/response side.

## Request line

```nim
req.getMethod()                 # HttpMethod (HttpGet, HttpPost, …)
req.getPath()                   # lent string  e.g. "/api/items/42"
req.getQuery()                  # lent string  raw query string "name=bob&age=4"
req.getUrl()                    # lent string  path + query
req.getClientIp()               # string
```

Routing is done with `case`/`if` on `getPath()` — the examples use
`case req.getMethod()` then compare `path`. `getPath()`/`getQuery()`/`getUrl()`
return `lent string` zero-copy views of the parser buffer.

## Headers

```nim
let headers = req.getHeaders()       # HttpHeaders
headers.getOrDefault("Content-Type", @["application/octet-stream"].HttpHeaderValues)
headers.getOrDefault("Cookie")
req.getContentLength()               # int, or -1 / 0 when absent
req.getConnectionClose()             # bool — "Connection: close"
```

## Body: buffered

For small bodies, read everything:

```nim
let bytes  = req.getBody()            # seq[byte]
let text   = req.getBodyString()      # string
req.bodyView()                        # (data: ptr UncheckedArray[byte], len: int)
```

## Body: streaming

`getBodyStream` returns a `BodyStream` you can consume in bounded chunks —
the memory-efficient path for large or hostile payloads. All methods take a
`maxLen` bound and never allocate more than asked.

```nim
var stream = req.getBodyStream()
while true:
  let chunk = stream.readChunk(64 * 1024)          # seq[byte]
  if chunk.len == 0: break
  # process chunk...

# alternatives:
stream.readChunkString(maxLen)               # string
stream.peekChunk(maxLen)                     # (data, len) without consuming
stream.drainChunk(len)                       # consume after peeking
stream.readChunkInto(buf, maxLen)            # reuse a seq
stream.peekAll()                             # (data, len) full remaining view
```

`readChunk(maxLen)`/`peekChunk(maxLen)` never return more than `maxLen` bytes,
so streaming stays bounded even with `maxBodySize = 0`.

## Multipart / file uploads

```nim
let mp = req.getMultipart(tmpDir = "")        # MultipartStreamerRef
let tmpFile = req.streamToFile(tmpDir = "")   # string — path to the temp file
```

`streamToFile` streams the raw body straight to a temp file (zero buffering).
See [multipart](multipart.md).

## Chunked / pipelining notes

The parser handles `Transfer-Encoding: chunked` internally; `req.getBody()` /
streaming reads see the decoded body. Pipelined requests are processed in order
by the server.

## API reference

Full signatures: [HTTP parser API](../api/http.md). Related: [server](server.md),
[multipart](multipart.md).
