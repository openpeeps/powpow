---
title: udp
description: "The UDP API: UdpSocket, bindUdp, connectUdp, sendTo and send."
keywords: ["powpow", "api", "udp", "socket"]
---

# udp

UDP socket support: bound (server) and connected (client) modes.
Source: `src/powpow/net/udp.nim`. Guide: [UDP](../net/udp.md).

## Types

```nim
OnUdpData* = proc(sender: Sockaddr_storage; data: openArray[byte]) {.closure.}

UdpSocket* = ref object
  fd*: SocketHandle
  loop*: Loop
```

## Procs

```nim
proc close*(sock: UdpSocket)

# sending to an address / cached sockaddr
proc sendTo*(sock: UdpSocket, data: openArray[byte], address: string, port: int): int {.inline.}
proc sendTo*(sock: UdpSocket, data: openArray[byte], addrBuf: Sockaddr_storage): int {.inline.}
proc sendTo*(sock: UdpSocket, data: string, address: string, port: int): int {.inline.}
proc sendTo*(sock: UdpSocket, data: string, addrBuf: Sockaddr_storage): int {.inline.}

# connected sockets only
proc send*(sock: UdpSocket, data: openArray[byte]): int {.inline.}
proc send*(sock: UdpSocket, data: string): int {.inline.}

# constructors
proc bindUdp*(loop: Loop, address: string, port: int, onData: OnUdpData): UdpSocket
proc connectUdp*(loop: Loop, address: string, port: int, onData: OnUdpData = nil): UdpSocket
```

## Related

- [common](common.md) — `Sockaddr_storage`, `sockaddrFromIp`
