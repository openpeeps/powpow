---
title: TCP chat room
description: "Low-level TcpServer broadcasting raw lines between connected clients."
keywords: ["powpow", "example", "tcp_chat"]
---

# TCP chat room

Drops down to the transport layer: a non-blocking `TcpServer` where every client's bytes are relayed to the others. Demonstrates accept/data/close wiring on `Connection` objects without any protocol framing.

Source: [`examples/tcp_chat.nim`](../../examples/tcp_chat.nim)

```nim
## examples/tcp_chat.nim — Multi-client TCP chat room (low-level transport).
##
## Demonstrates powpow's low-level TCP layer: a non-blocking `TcpServer` that
## accepts many clients and broadcasts each client's bytes to everyone else.
##
## Run:
##   nim c -r examples/tcp_chat.nim
##
## Test (from one or more terminals):
##   nc 127.0.0.1 9010
##   # or use the bundled interactive client:
##   nim c -r --threads:on examples/tcp_client.nim

import ../src/powpow
import std/[strutils, sequtils]

const Port = 9010

var clients: seq[Connection]

proc broadcast(fromConn: Connection, text: string) =
  ## Send `text` to every connected client except `fromConn`.
  for c in clients:
    if c.fd != fromConn.fd:
      discard c.send(text)

let loop = newLoop()

let server = newTcpServer(loop,
  onAccept = proc(conn: Connection) =
    clients.add(conn)
    echo "⚡ client joined (fd=", conn.fd.int, ", total=", clients.len, ")"
    broadcast(conn, "* client " & $conn.fd.int & " joined\n")
  ,
  onData = proc(conn: Connection, data: openArray[byte]) =
    let text = $cast[string](@data)
    echo "fd=", conn.fd.int, " says: ", text.strip()
    broadcast(conn, "<" & $conn.fd.int & "> " & text)
  ,
  onClose = proc(conn: Connection) =
    let fd = conn.fd.int
    clients.keepItIf(it.fd.int != fd)
    echo "⚡ client left (fd=", fd, ", total=", clients.len, ")"
    broadcast(conn, "* client " & $fd & " left\n")
  ,
)

server.listen("0.0.0.0", Port)
echo "⚡ TCP chat server listening on 0.0.0.0:" & $Port
echo "  Connect with:  nc 127.0.0.1 " & $Port
echo "  Press Ctrl+C to stop"
loop.run()
```

## Running

```bash
nim c -r examples/tcp_chat.nim
```

## Try it

```bash
nc 127.0.0.1 9010
nim c -r examples/tcp_client.nim   # bundled interactive client
```

## How it works

- `newTcpServer(loop, onAccept=..., onData=..., onClose=...)` is the whole API surface; `conn.fd` identifies peers.
- `Connection.send(data)` queues a write; discardable return value.
- No framing: whatever bytes arrive are broadcast as-is, which is why terminal clients should send line-buffered input.

[TCP guide](../net/tcp.md) and [TCP API](../api/tcp.md).

