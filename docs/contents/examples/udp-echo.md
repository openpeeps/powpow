---
title: UDP echo server
description: "Datagram echo with sender addressing plus a bundled ping client mode."
keywords: ["powpow", "example", "udp_echo"]
---

# UDP echo server

Binds a `UdpSocket` and echoes datagrams back to their senders, formatting peer addresses with `getnameinfo`. A `--client` flag flips the same file into a ping client that connects UDP, sends once, prints the reply, and exits on a timer.

Source: [`examples/udp_echo.nim`](../../examples/udp_echo.nim)

```nim
## examples/udp_echo.nim — UDP echo server + bundled ping client.
##
## Demonstrates powpow's UDP layer: a bound `UdpSocket` that receives datagrams
## via `onData` (with the sender's address) and echoes them back with `sendTo`,
## plus a `--client` mode that pings the server with `connectUdp`.
##
## Run (server):
##   nim c -r examples/udp_echo.nim
##
## Test with the built-in client (another terminal):
##   nim c -r examples/udp_echo.nim -- --client
##
## Or with netcat:
##   echo "hello udp" | nc -u -w1 127.0.0.1 9011

import ../src/powpow
import std/[strutils, os]

const Host = "127.0.0.1"
const Port = 9011

proc senderAddr(sa: Sockaddr_storage): tuple[ip: string; port: int] =
  ## Format a `Sockaddr_storage` into "ip:port" using getnameinfo (numeric).
  const NI_MAXHOST = 1025
  const NI_NUMERICHOST = 1
  const NI_NUMERICSERV = 2
  var host: array[NI_MAXHOST, char]
  var serv: array[16, char]
  let saPtr = cast[ptr Sockaddr](unsafeAddr sa)
  let saLen = getSockLen(unsafeAddr sa)
  when defined(windows):
    if getnameinfo(saPtr, saLen, cast[cstring](addr host[0]), NI_MAXHOST.DWORD,
                   cast[cstring](addr serv[0]), 16.DWORD,
                   NI_NUMERICHOST or NI_NUMERICSERV) == 0:
      result = ($cast[cstring](addr host[0]),
                try: parseInt($cast[cstring](addr serv[0])) except ValueError: 0)
  else:
    if getnameinfo(saPtr, saLen, cast[cstring](addr host[0]), host.len.SockLen,
                   cast[cstring](addr serv[0]), serv.len.SockLen,
                   NI_NUMERICHOST or NI_NUMERICSERV) == 0:
      result = ($cast[cstring](addr host[0]),
                try: parseInt($cast[cstring](addr serv[0])) except ValueError: 0)
    else:
      result = ("unknown", 0)

proc runServer() =
  let loop = newLoop()
  var server: UdpSocket
  server = loop.bindUdp("0.0.0.0", Port,
    onData = proc(sender: Sockaddr_storage; data: openArray[byte]) =
      let fromAddr = senderAddr(sender)
      let text = $cast[string](@data)
      echo "← ", fromAddr.ip, ":", fromAddr.port, " says: ", text
      let n = server.sendTo(text, fromAddr.ip, fromAddr.port)
      echo "→ echoed ", n, " bytes"
  )
  echo "⚡ UDP echo server listening on 0.0.0.0:" & $Port
  echo "  Ping it with:   nim c -r examples/udp_echo.nim -- --client"
  echo "  Press Ctrl+C to stop"
  loop.run()

proc runClient() =
  let loop = newLoop()
  let sock = loop.connectUdp(Host, Port,
    onData = proc(sender: Sockaddr_storage; data: openArray[byte]) =
      echo "→ echo reply: ", $cast[string](@data)
  )
  echo "⚡ UDP client connected to ", Host, ":", Port, " — sending a ping"
  discard sock.send("ping from powpow!")
  discard loop.addTimer(2000) do (id: int):
    sock.close()
    loop.stop()
  loop.run()

if paramCount() > 0 and paramStr(1) == "--client":
  runClient()
else:
  runServer()
```

## Running

```bash
nim c -r examples/udp_echo.nim
```

## Try it

```bash
echo "hello udp" | nc -u -w1 127.0.0.1 9011
nim c -r examples/udp_echo.nim -- --client
```

## How it works

- `loop.bindUdp(host, port, onData=...)` delivers datagrams plus a `Sockaddr_storage` identifying the sender.
- `sock.sendTo(text, ip, port)` targets arbitrary peers; connected sockets can also use plain `send`.
- `connectUdp(loop, host, port, onData=...)` pins the client to one peer so replies arrive on the same socket.
- Timers (`addTimer`) provide the client's self-termination after 2 seconds.

[UDP guide](../net/udp.md) and [UDP API](../api/udp.md).

