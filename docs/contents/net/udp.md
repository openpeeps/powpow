---
title: UDP
description: "Bound and connected UDP sockets on the powpow loop: bindUdp, connectUdp, sendTo and send."
keywords: ["powpow", "udp", "datagram", "socket"]
---

# UDP

`net/udp.nim` provides non-blocking UDP sockets in two modes: **bound**
(server-style, receives from anyone) and **connected** (client-style, scoped to
one peer).

Runnable example: [`examples/udp_echo.nim`](../../examples/udp_echo.nim).

## Bound UDP socket (server)

```nim
let sock = bindUdp(loop, "0.0.0.0", 9011,
  proc(sender: Sockaddr_storage; data: openArray[byte]) =
    sock.sendTo(data, sender)     # echo back to the sender
)
```

The callback receives the sender's address and the datagram bytes. `OnUdpData =
proc(sender: Sockaddr_storage; data: openArray[byte]) {.closure.}`

## Connected UDP socket (client)

```nim
let sock = connectUdp(loop, "127.0.0.1", 9011, onData)
sock.send("ping")
```

A connected UDP socket can `send` (no address) and only receives datagrams from
its peer.

## Sending

```nim
sock.sendTo(data, "example.com", 1234)    # resolve each call (address form)
sock.sendTo(data, addrBuf)                # use a cached Sockaddr_storage
sock.send(data)                           # connected sockets only
```

The address forms re-resolve per datagram (see [async DNS](../core/dns.md) for the
run-time resolver); `sockaddrFromIp` from [sockets](sockets.md) is the cheap way
to build a fixed destination.

## Closing

```nim
sock.close()
```

## API reference

Full signatures: [UDP API](../api/udp.md). Related: [sockets](sockets.md),
[TCP](tcp.md).
