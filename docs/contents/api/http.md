---
title: http
description: "The HTTP parser and HttpRequest API: parser procs, request accessors, streaming body and multipart."
keywords: ["powpow", "api", "http", "parser", "request"]
---

# http

Incremental zero-copy HTTP/1.1 request parser and the `HttpRequest` view.
Source: `src/powpow/proto/http.nim`.
Guides: [parser](../http/parser.md), [requests](../http/requests.md).

## Constants

```nim
MaxHeaderSize* = 8192
MaxRequestLine* = 8192
MaxHeaders* = 100
DefaultBodyBuf* = 65536
MaxStreamBodySize* = 512 * 1024 * 1024
```

## Enum

```nim
ParsePhase* = enum PhaseRequestLine, PhaseHeaders, PhaseBody, PhaseComplete, PhaseError
```

## Types

```nim
HttpBodyCallback* = proc(data: openArray[byte]; done: bool) {.closure.}

HttpParser* = ref object
  buf*: seq[byte]
  bufLen*: int
  maxBodySize*: int64
  maxStreamBodySize*: int64
  headerEnd*: int
  contentLength*: int
  connectionClose*: bool
  expectContinue*: bool
  onBodyData*: HttpBodyCallback
  methodCache*: HttpMethod
  phase*: ParsePhase

HttpRequest* = ref object
  parser*: HttpParser
  httpMethod*: HttpMethod
  conn*: Connection
  streamer*: MultipartStreamerRef
  streamPath*: string
  urlVal*: string
  headersVal*: HttpHeaders
  headersReady*: bool
  bodyVal*: seq[byte]
  bodyReady*: bool

BodyStream* = object               # streaming body cursor (parser + readPos)
```

## Parser procs

```nim
proc newHttpParser*(initialBufSize = 4096): HttpParser
proc reset*(p: HttpParser)
proc resetForNext*(p: HttpParser)
func phase*(p: HttpParser): ParsePhase {.inline.}
proc feed*(p: HttpParser, data: openArray[byte]): ParsePhase {.discardable.}
proc feed*(p: HttpParser, data: string): ParsePhase {.inline, discardable.}
proc tryAdvance*(p: HttpParser)
func isComplete*(p: HttpParser): bool {.inline.}
func isError*(p: HttpParser): bool {.inline.}
proc setError*(p: HttpParser, code: HttpCode) {.inline.}
func error*(p: HttpParser): HttpCode {.inline.}
func peekMethod*(p: HttpParser): HttpMethod {.inline.}
proc peekPath*(p: HttpParser): lent string {.inline.}
proc peekContentType*(p: HttpParser): lent string {.inline.}
proc getRequest*(p: HttpParser): HttpRequest
proc getRemainingData*(p: HttpParser): seq[byte]          # pipelined bytes
func headerBytes*(req: HttpRequest): int {.inline.}
proc getBodyView*(p: HttpParser): tuple[data: ptr UncheckedArray[byte]; len: int]
```

## Request accessors

```nim
proc getMethod*(req: HttpRequest): HttpMethod {.inline.}
proc getPath*(req: HttpRequest): lent string
proc getQuery*(req: HttpRequest): lent string
proc getUrl*(req: HttpRequest): lent string
proc getHeaders*(req: HttpRequest): HttpHeaders
func getContentLength*(req: HttpRequest): int {.inline.}
func getConnectionClose*(req: HttpRequest): bool {.inline.}
proc getClientIp*(req: HttpRequest): string {.inline.}

# buffered body
proc getBody*(req: HttpRequest): seq[byte]
proc getBodyString*(req: HttpRequest): string
proc bodyView*(req: HttpRequest): tuple[data: ptr UncheckedArray[byte]; len: int]

# streaming body
proc getBodyStream*(req: HttpRequest): BodyStream
proc readChunk*(stream: var BodyStream; maxLen: Natural): seq[byte]
proc readChunkString*(stream: var BodyStream; maxLen: Natural): string
proc peekChunk*(stream: var BodyStream; maxLen: Natural): tuple[data: ptr UncheckedArray[byte]; len: int]
proc drainChunk*(stream: var BodyStream; len: Natural) {.inline.}
proc readChunkInto*(stream: var BodyStream; buf: var seq[byte]; maxLen: Natural): int
proc peekAll*(stream: BodyStream): tuple[data: ptr UncheckedArray[byte]; len: int]

# multipart / streaming to file
proc getMultipart*(req: HttpRequest; tmpDir = ""): MultipartStreamerRef
proc streamToFile*(req: HttpRequest; tmpDir = ""): string
```

## Related

- [httpserver](httpserver.md) — feeds the parser and dispatches requests
- [multipart](../http/multipart.md) — upload handling
