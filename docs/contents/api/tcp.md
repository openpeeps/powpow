---
title: tcp
description: "The TCP API: Connection, TcpServer, send/sendv, closeAfterDrain, sendfile and async connect."
keywords: ["powpow", "api", "tcp", "connection", "server"]
---

# tcp

Non-blocking TCP server/client with connection pooling, write buffering/corking,
scatter-gather writes and zero-copy file send. Source: `src/powpow/net/tcp.nim`.
Guide: [TCP](../net/tcp.md).

## Constants

```nim
MaxBufPoolSize* = 1024
MaxConnPoolSize* = 1024
```

## Enum

```nim
ConnState* = enum Connecting, Connected, Closing, Closed
```

## Types

```nim
Connection* = ref object
  fd*: SocketHandle
  loop*: Loop
  server*: TcpServer
  state*: ConnState
  clientIp*: string
  sendFileFd*: int
  sendFileOff*: int64
  sendFileRemain*: int64
  data*: pointer
  ssl*: pointer
  tlsState*: TlsState

OnAccept* = proc(conn: Connection) {.closure.}
OnData*   = proc(conn: Connection, data: openArray[byte]) {.closure.}
OnClose*  = proc(conn: Connection) {.closure.}
OnError*  = proc(err: string) {.closure.}

TcpServer* = ref object
  fd*: SocketHandle
  loop*: Loop
  onClose*: OnClose
  connPool*: seq[Connection]
  maxConnections*: int
```

## Procs

```nim
# buffer pooling
proc acquireBuf*(loop: Loop): ptr UncheckedArray[byte] {.inline.}
proc releaseBuf*(loop: Loop, buf: ptr UncheckedArray[byte]) {.inline.}

# TLS helpers (see tls.md)
proc driveHandshake*(conn: Connection): bool
proc tlsRead*(conn: Connection, buf: pointer, count: int): int
proc tlsWrite*(conn: Connection, buf: pointer, count: int): int
proc tlsFree*(conn: Connection)

# connection I/O
proc close*(conn: Connection)
proc send*(conn: Connection, data: openArray[byte]): int
proc send*(conn: Connection, data: string): int
proc sendv*(conn: Connection, parts: openArray[tuple[data: ptr UncheckedArray[byte], len: int]]): int
proc shutdown*(conn: Connection)
proc closeAfterDrain*(conn: Connection) {.inline.}
proc closeAndRelease*(conn: Connection) {.inline.}
proc continueSendFile*(conn: Connection): bool
proc getClientIp*(conn: Connection): string {.inline.}
proc getClientSockAddr*(conn: Connection): Sockaddr_storage {.inline.}

# server
proc listen*(server: TcpServer, address: string, port: int)
proc listenUnix*(server: TcpServer, path: string; mode: int = 0o660)   # POSIX
proc close*(server: TcpServer)
proc injectFd*(server: TcpServer, clientFd: SocketHandle)
proc newTcpServer*(loop: Loop, onData: OnData, onAccept: OnAccept = nil,
                   onClose: OnClose = nil): TcpServer

# client (async connect, DNS resolved on the loop)
proc connect*(loop: Loop, address: string, port: int,
              onConnect: proc(conn: Connection) {.closure.},
              onData: OnData, onClose: OnClose = nil, onError: OnError = nil)
proc connectUnix*(loop: Loop; path: string;
                  onConnect: proc(conn: Connection) {.closure.};
                  onData: OnData; onClose: OnClose = nil)             # POSIX
```

## io_uring (`when iouEnabled`)

Under the io_uring backend (`-d:powpowIoUring`), the same `Connection` API is
driven by submission ops instead of readiness events:

- `send`/`sendv` use `IORING_OP_SEND`, upgrading to **`IORING_OP_SEND_ZC`** for
  payloads at or above `SendZcThreshold` (64 KiB, `-d:powpowSendZcThreshold`);
  `-d:powpowSendZcFixed` routes them through `SEND_ZC_FIXED` against a
  registered per-loop buffer.
- file sends (`sendFileFd` / `continueSendFile`) use **`IORING_OP_SPLICE`**
  (file → pipe → socket) by default, falling back to a `READ` + `SEND` pump.
- graceful close uses `IORING_OP_SHUTDOWN` by default — submitted with
  `IOSQE_CQE_SKIP_SUCCESS` once the kernel verifies the opcode (falling back to
  `sockShutdown(2)` when it is rejected), so it costs no syscall and no CQE.

See the [io_uring guide](../io_uring.md).

## Related

- [common](common.md) — socket primitives
- [tls](tls.md) — `wrapTls` on a `Connection`
- [dns](dns.md) — async connect resolution
