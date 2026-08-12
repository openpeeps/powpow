---
title: stream
description: "The IoStream API: openStream, write, pause/resume, closeAfterWrite, newStreamPair and the MaxIoStreamWriteBuffer cap."
keywords: ["powpow", "api", "stream", "iostream", "pipe", "socketpair"]
---

# stream

Raw-fd streaming for arbitrary non-blocking file descriptors, integrated with
the loop. Source: `src/powpow/stream.nim`. POSIX only (compiles away on
Windows). Guide: [Streams](../core/streams.md).

## Const

```nim
MaxIoStreamWriteBuffer* = 32 * 1024 * 1024   # queued-write cap (bytes)
```

## Enum

```nim
IoStreamState* = enum
  StreamOpen
  StreamClosed
```

## Types

```nim
IoStream* = ref object
  fd*:      int
  loop*:    Loop
  state*:   IoStreamState
  onClose*: proc(s: IoStream) {.closure.}
  data*:    pointer           # user state, like Connection
```

## Procs

```nim
proc openStream*(loop: Loop, fd: int,
                 onData: proc(s: IoStream, data: openArray[byte]) {.closure.},
                 onClose: proc(s: IoStream) {.closure.} = nil): IoStream

proc write*(s: IoStream, data: openArray[byte]): int
proc write*(s: IoStream, data: string): int

proc pause*(s: IoStream)                 # stop reading (backpressure)
proc resume*(s: IoStream)                # re-arm reading, drain buffered data

proc closeAfterWrite*(s: IoStream)       # flush pending writes, then close

proc close*(s: IoStream)                 # terminal; fires onClose exactly once

proc newStreamPair*(loop: Loop,
                    onData: proc(s: IoStream, data: openArray[byte]) {.closure.},
                    onClose: proc(s: IoStream) {.closure.} = nil,
                    onData2: proc(s: IoStream, data: openArray[byte]) {.closure.} = nil,
                    onClose2: proc(s: IoStream) {.closure.} = nil
                   ): (IoStream, IoStream)   # full-duplex socketpair
```

## Related

- [loop](loop.md) — streams are driven by the loop's fd watchers
- [fswatch](fswatch.md) — the other fd-based integration in the same family
