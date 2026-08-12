---
title: common
description: "The net/common API: socket helpers, resolution, options, raw I/O, file helpers and sendfile."
keywords: ["powpow", "api", "sockets", "common", "sendfile"]
---

# common

Platform-agnostic socket helpers, address resolution, socket options, zero-copy
sendfile and error handling. Source: `src/powpow/net/common.nim`.
Guide: [Sockets](../net/sockets.md).

On POSIX this module re-exports `std/posix`, so the raw syscalls
(`socket`, `bind`, `connect`, `send`, `recv`, `accept`, …) are also in scope.

## Types

```nim
SocketHandle* = cint
SockLen* = cint
DWORD* = uint32            # Windows

Sockaddr* / Sockaddr_in* / Sockaddr_in6* / Sockaddr_storage* / AddrInfo* / TLinger* / IOVec*

NetError* = object of CatchableError
```

## Constants

```nim
SendFileChunkSize* = 65536
DefaultSendFileChunk* = 0
DefaultBufSize* = 4096
O_RDONLY* = 0
SEEK_SET* / SEEK_CUR* / SEEK_END*
UNIX_PATH_MAX* = 107       # POSIX
```

Windows-only constants: `NI_NUMERICHOST`, `NI_MAXHOST`, `SOCK_STREAM`,
`SOCK_DGRAM`, `SOL_SOCKET`, `SO_REUSEADDR`, `SO_LINGER`, `SO_ERROR`,
`IPPROTO_TCP`, `TCP_NODELAY`, `AF_UNSPEC`, `AF_INET`, `AF_INET6`, `AI_PASSIVE`,
`SOMAXCONN`, `FIONBIO`, `WSAEWOULDBLOCK`, `WSAEINPROGRESS`, `WSAENETDOWN`,
`WSAECONNRESET`, `WSAESHUTDOWN`.

## Procs

```nim
proc initNet*()
proc lastSocketError*(): cint {.inline.}

# socket options
proc setNonBlocking*(fd: SocketHandle)
proc setReuseAddr*(fd: SocketHandle)
proc setReusePort*(fd: SocketHandle)
proc setTcpNoDelay*(fd: SocketHandle)
proc setTcpCork*(fd: SocketHandle, enable: bool)
proc setIpv6Only*(fd: SocketHandle)

# address resolution
proc resolveAddrAll*(address: string, port: int, sockType = SOCK_STREAM, protocol = 0): seq[Sockaddr_storage]
proc resolveAddr*(address: string, port: int, sockType = SOCK_STREAM, protocol = 0): Sockaddr_storage
proc isIpAddress*(address: string): bool
proc sockaddrFromIp*(ip: string, port: int): Sockaddr_storage
proc getSockLen*(addrBuf: ptr Sockaddr_storage): SockLen {.inline.}

# errors
proc sockWouldBlock*(): bool {.inline.}
proc sockInterrupted*(): bool {.inline.}
proc sockInProgress*(): bool {.inline.}

# raw I/O
proc sockRecv*(fd: SocketHandle, buf: pointer, bufLen: int): int {.inline.}
proc sockSend*(fd: SocketHandle, buf: pointer, len: int): int {.inline.}
proc sockClose*(fd: SocketHandle) {.inline.}
proc sockShutdown*(fd: SocketHandle, how: cint) {.inline.}
proc sockWritev*(fd: SocketHandle, iov: ptr IOVec, iovcnt: int): int {.inline.}

# file helpers
proc openFileRead*(path: string): int
proc getFileSize*(fd: int): int64
proc closeFile*(fd: int) {.inline.}
proc readFile*(fd: int; buf: ptr UncheckedArray[byte]; len: int): int64
proc seekFile*(fd: int; offset: int64): int64

# zero-copy sendfile
proc sendFileChunk*(sockFd: SocketHandle; fileFd: int; fileOff: var int64; remaining: var int64): int64
```

Windows-only bindings (Winsock): `socket`, `bindSocket`, `listen`, `accept`,
`connect`, `send`, `recv`, `closesocket`, `shutdown`, `setsockopt`,
`getsockopt`, `ioctlsocket`, `sendto`, `recvfrom`, `wsagetlasterror`,
`getaddrinfo`, `freeaddrinfo`, `getnameinfo`, `getpeername`.

## Related

- [tcp](tcp.md), [udp](udp.md), [dns](dns.md)
