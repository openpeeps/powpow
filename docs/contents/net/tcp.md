---
title: TCP
description: "Non-blocking TCP servers and clients on the powpow loop: connection pooling, corking, sendv, zero-copy file send and graceful shutdown."
keywords: ["powpow", "tcp", "networking", "server", "client"]
---

# TCP

`net/tcp.nim` provides non-blocking TCP servers and clients built on the event
loop: connection pooling, write buffering with corking, scatter-gather writes
(`sendv`), zero-copy file send, and graceful close-after-drain.

Runnable examples: [`examples/tcp_chat.nim`](../../examples/tcp_chat.nim),
[`examples/tcp_client.nim`](../../examples/tcp_client.nim),
[`examples/tcp_proxy.nim`](../../examples/tcp_proxy.nim).

## TCP server

```nim
let loop = newLoop()

let server = newTcpServer(
  loop,
  onData  = proc(conn: Connection, data: openArray[byte]) =
    discard conn.send(data),          # echo
  onAccept = proc(conn: Connection) =
    echo "client connected: ", conn.getClientIp(),
  onClose  = proc(conn: Connection) =
    echo "client disconnected")

server.listen("0.0.0.0", 9010)        # or server.listenUnix("/tmp/sock")
loop.run()
```

`newTcpServer` returns a `TcpServer` with public fields `fd`, `loop`, `onClose`,
`connPool` and `maxConnections`.

`listenUnix(path, mode = 0o660)` binds a Unix domain socket instead of TCP
(POSIX). `injectFd(server, clientFd)` lets you hand a pre-accepted fd to the
server (used by the HTTP server's upgrade path).

## TCP client (async connect)

```nim
connect(loop, "example.com", 443,
  onConnect = proc(conn: Connection) = conn.send("GET / HTTP/1.1\r\n\r\n"),
  onData    = proc(conn: Connection, data: openArray[byte]) =
    stdout.write(cast[string](data)),
  onClose   = proc(conn: Connection) = echo "closed",
  onError   = proc(err: string) = echo "failed: ", err)
```

Hostnames are resolved **on the loop** via the [async DNS resolver](../core/dns.md);
DNS failure arrives through `onError`. `connectUnix(path, onConnect, onData,
onClose)` connects to a Unix socket (POSIX).

## Sending data

```nim
conn.send(data: openArray[byte])      # int bytes sent
conn.send(data: string)               # int bytes sent
conn.sendv([(bufPtr, len), (bufPtr, len)])   # scatter-gather, one syscall
```

Writes are buffered and corked (`TCP_CORK`/`TCP_NOPUSH`) automatically, flushed
by the loop when the connection becomes writable.

## Zero-copy file send

`Connection` carries a sendfile state machine; the HTTP server uses this for
`sendFile`/`streamFile`:

```nim
conn.sendFileFd = fileFd              # open with openFileRead()
conn.sendFileOff = 0
conn.sendFileRemain = fileSize
while conn.continueSendFile():         # returns false when done
  discard
```

Under the **io_uring** backend the transfer is driven by `IORING_OP_SPLICE`
(file → pipe → socket) with no user-space copy; see the
[io_uring guide](../io_uring.md).

## Closing

```nim
conn.close()             # immediate close (SO_LINGER{0} fast shutdown)
conn.shutdown()          # stop the write side
conn.closeAfterDrain()   # close once the send buffer is fully flushed
conn.closeAndRelease()   # close and return buffers to the pool
```

Graceful shutdown: `closeAfterDrain` guarantees buffered data is sent before the
connection tears down.

## Connection details

`Connection` public fields: `fd`, `loop`, `server`, `state`
(`ConnState`: `Connecting`, `Connected`, `Closing`, `Closed`), `clientIp`,
`data` (free per-connection pointer), `ssl`/`tlsState` (TLS layer).

```nim
conn.getClientIp()          # string
conn.getClientSockAddr()    # Sockaddr_storage
```

## Buffer pooling

Read buffers come from the loop pool:

```nim
let buf = loop.acquireBuf()
let n = sockRecv(conn.fd, buf, DefaultBufSize)
loop.releaseBuf(buf)
```

`MaxBufPoolSize` = 1024, `MaxConnPoolSize` = 1024.

## API reference

Full signatures: [TCP API](../api/tcp.md). Related: [sockets](sockets.md),
[UDP](udp.md), [TLS](tls.md).
