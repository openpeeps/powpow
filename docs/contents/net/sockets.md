---
title: Sockets (net/common)
description: "Platform-agnostic socket helpers, address resolution, socket options, zero-copy sendfile and file helpers."
keywords: ["powpow", "sockets", "net", "sendfile", "socket options"]
---

# Sockets (net/common)

`net/common.nim` is the platform-agnostic socket layer underneath TCP and UDP.
It is auto-initialized at module load (`initNet()`), and on POSIX it re-exports
`std/posix`, so the raw `socket`/`bind`/`connect`/`send`/`recv`/`accept`/…
syscalls are also in scope.

## Address resolution

```nim
let addrBuf = resolveAddr("example.com", 443)              # first result
let all     = resolveAddrAll("example.com", 443)           # all results
let ip      = sockaddrFromIp("127.0.0.1", 9000)            # literal only
isIpAddress("10.0.0.1")                                    # true
```

`resolveAddr*` uses the platform resolver (`getaddrinfo`) and is the blocking
path used at startup (e.g. `tcp.listen`). For run-time resolution on the loop,
use [async DNS](../core/dns.md).

## Socket options

```nim
setNonBlocking(fd)
setReuseAddr(fd)
setReusePort(fd)
setTcpNoDelay(fd)
setTcpCork(fd, enable = true)
setIpv6Only(fd)
```

## Raw I/O wrappers

```nim
sockSend(fd, addr buf, buf.len)
sockRecv(fd, addr buf, buf.len)
sockWritev(fd, iov, iovcnt)
sockClose(fd)
sockShutdown(fd, how)
lastSocketError()
sockWouldBlock()       # errno == EAGAIN/EWOULDBLOCK
sockInterrupted()      # errno == EINTR
sockInProgress()       # errno == EINPROGRESS
getSockLen(addr sockaddr)      # length of the sockaddr structure
```

## Zero-copy file transmission

`sendfile` moves file bytes to a socket without bouncing them through userspace:

```nim
var off: int64 = 0
var remain: int64 = fileSize
while remain > 0:
  let n = sendFileChunk(sockFd, fileFd, off, remain)   # 0 = EOF, -1 = error
  if n <= 0: break
  remain -= n
```

`SendFileChunkSize` is 65536; `DefaultSendFileChunk` is 0 (send all).
On Windows powpow uses `TransmitFile` instead.

## File helpers

```nim
let fd = openFileRead("/path/to/file")
let size = getFileSize(fd)
readFile(fd, buf, bufLen)      # int64 bytes read
seekFile(fd, offset)
closeFile(fd)
```

## Errors

All socket/network errors surface as `NetError* = object of CatchableError`.

## Unix domain sockets

`listenUnix` / `connectUnix` (TCP and HTTP) are POSIX-only. `UNIX_PATH_MAX`
is 107.

## API reference

Full signatures: [common API](../api/common.md). Also see [TCP](tcp.md) and
[UDP](udp.md).
