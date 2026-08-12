---
title: WebSocket
description: "RFC 6455 WebSocket servers in powpow: standalone mode, HTTP-upgrade mode, frame types, and security caps."
keywords: ["powpow", "websocket", "ws", "realtime"]
---

# WebSocket

`proto/ws.nim` is a RFC 6455-compliant WebSocket implementation in two modes:

1. **Standalone** — a dedicated WebSocket server that handles the upgrade
   handshake internally (no HTTP routes).
2. **Upgrade** — a WebSocket endpoint on an existing `HttpServer` route, so HTTP
   and WebSocket share one port.

Runnable examples: [`examples/wsserver.nim`](../examples/wsserver.nim),
[`examples/ws_chat.nim`](../examples/ws_chat.nim),
[`examples/wsupgrade.nim`](../examples/wsupgrade.nim).

## Frame types

`WsFrameKind`:

| Value | Meaning |
|---|---|
| `wsContinuation` | continuation of a fragmented message |
| `wsText` | text frame |
| `wsBinary` | binary frame |
| `wsClose` | close handshake |
| `wsPing` | ping (reply `wsPong`) |
| `wsPong` | pong |

## Standalone server

```nim
let wss = newWsServer(loop)          # or newWsServer() for its own loop

wss.onOpen(proc(ws: WsConnection) = echo "client connected")
wss.onMessage(proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
  ws.sendText("echo: " & cast[string](data)))
wss.onClose(proc(ws: WsConnection, code: int, reason: string) = echo "bye")
wss.onError(proc(ws: WsConnection, err: string) = echo "err: ", err)

wss.listen("0.0.0.0", 9001)
wss.start()
```

`handshakeCount()` reports in-flight handshakes.

## WebSocket over HTTP (same port)

Use `websocketUpgrade` inside a route handler. It performs the upgrade and
returns the `WsConnection`; HTTP keeps serving other paths.

```nim
proc handler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  if req.getPath() == "/ws":
    discard websocketUpgrade(res, req, server,
      onMessage = proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
        ws.sendText("echo: " & cast[string](data)))
  else:
    res.send("<h1>HTTP on the same port</h1>")

let server = newHttpServer()
server.start(handler, Port(9000))
```

## Sending and closing

```nim
ws.sendText(s)                    # text frame
ws.sendBinary(data)               # binary frame
ws.sendPing(data = [])            # ping
ws.sendPong(data = [])            # pong
ws.closeWs(code = 1000, reason = "")   # close handshake
```

Low-level frame helpers on `Connection`:
`writeFrame(conn, opcode, payload)`, `writeFrameMasked(conn, opcode, payload, mask)`,
`computeAcceptKey(clientKey)`, `buildHandshakeResponse(acceptKey)`,
`sendHandshake(conn, clientKey)`. `parseWsFrames(ws, data)` feeds raw bytes into
the frame parser; `WsFrameParser.reset` clears it.

## Configuration & limits

`WsServer` public fields:

| Field | Purpose |
|---|---|
| `maxFrameSize` | max frame payload (`DefaultMaxFrameSize` = 10 MB) |
| `handshakeTimeoutMs` | close upgrades that never finish the handshake |
| `maxHandshakeSessions` | cap in-flight handshakes (stall-DoS defense) |
| `idleTimeoutMs` | post-upgrade idle close |

Per-message deflate is supported. Frame caps still apply in
`maxFrameSize = 0` ("unlimited") mode — see [security](security.md).

## API reference

Full signatures: [WebSocket API](api/ws.md). Related: [server](http/server.md).
