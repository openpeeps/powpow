---
title: Streams (raw-fd I/O)
description: "Drive arbitrary non-blocking file descriptors from the powpow loop with IoStream: pipes, subprocess stdout, socketpair IPC, regular-file fds (kqueue), with write buffering and read backpressure."
keywords: ["powpow", "stream", "iostream", "pipe", "socketpair", "ipc", "raw fd", "backpressure"]
---

# Streams (raw-fd I/O)

`stream.nim` exposes `IoStream`, a wrapper that drives an arbitrary non-blocking
file descriptor from the event loop — the same machinery `Connection` uses, but
for any fd, not just sockets.

Runnable example: [`examples/stream_pipe.nim`](../../examples/stream_pipe.nim).

## What it enables

- **Pipes** — read from / write to `pipe(2)` ends
- **Subprocess stdout / stdin** — a pipe pair handed to `fork`/`exec`
- **IPC** — `socketpair(AF_UNIX, SOCK_STREAM)` full-duplex channels
- **Unix domain sockets** (in addition to the TCP-based `listenUnix`)
- **Regular-file fds** on macOS/BSD (see [platform notes](#platform-notes))

## Creating a stream

`openStream` takes ownership of an fd and registers a read watcher on the loop:

```nim
let s = openStream(loop, pipeFd,
  onData  = proc(s: IoStream, data: openArray[byte]) =
    # delivered per read chunk (edge-triggered drain, 4 KiB read buffer)
    echo "got ", data.len, " bytes"
  ,
  onClose = proc(s: IoStream) =
    echo "closed")
```

The fd is set non-blocking for you. For a full-duplex channel, `newStreamPair`
creates a `socketpair` and returns both ends:

```nim
proc toStr(data: openArray[byte]): string =     # openArray -> string copy
  result = newString(data.len)
  if data.len > 0:
    copyMem(addr result[0], unsafeAddr data[0], data.len)

var a, b: IoStream
(a, b) = newStreamPair(loop,
  onData = proc(s: IoStream, data: openArray[byte]) =
    discard b.write("echo: " & data.toStr()))
```

> Note: `cast[string](data)` on an `openArray[byte]` is **not** valid — it reads
> the length header from inside the buffer. Copy via `toStr` (above) instead.
```

## Writing

`write` mirrors `Connection.send`: it tries a direct write, drains until
`EAGAIN`, then buffers the remainder and watches for writability:

```nim
discard s.write("hello")     # openArray[byte] or string
```

- Returns the full `data.len` when accepted (sent or buffered).
- Returns `-1` on a hard error (e.g. `EPIPE` when the peer closed) — the stream
  is closed and `onClose` fires. SIGPIPE is globally ignored by powpow, so this
  never crashes your process.
- A queued-write cap (32 MiB by default, `MaxIoStreamWriteBuffer`) protects
  against a slow reader accumulating unbounded memory.

## Backpressure

**Reads** — `pause()` removes the read watch (no more `onData` until
`resume()`). A paused reader stops draining the fd, the kernel buffer fills, and
the writer blocks — which is exactly the point of pipes. Pending writes still
flush while paused.

```nim
s.pause()       # stop reading; apply backpressure to the writer
s.resume()      # re-arm the read watch and drain anything buffered meanwhile
```

**Writes** — partial writes are buffered and flushed via the loop's Write
events, so a slow consumer can never stall the loop.

## Closing

`close` is the single terminal transition: it unregisters the fd, closes it,
returns the read buffer, and fires `onClose` **exactly once** — whether reached
by peer EOF, a hard error, or an explicit call.

```nim
s.close()                # fire-and-forget; onClose fires once
s.closeAfterWrite()      # flush pending writes, then close (EOF to the peer)
```

## Platform notes

| fd type | macOS / BSD (kqueue) | Linux (epoll) | Windows |
|---|---|---|---|
| pipe / socketpair / UDS | yes | yes | not yet (IOCP is sockets-only) |
| regular file | yes (`EVFILT_READ`) | no (epoll rejects regular files) | — |

Regular-file streaming on Linux belongs to the planned thread-pool work, and the
whole module compiles to nothing on Windows (same posture as the signal
self-pipe).

## API reference

Full signatures: [stream API](../api/stream.md).
