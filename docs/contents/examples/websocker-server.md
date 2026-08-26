---
title: Standalone WebSocket server
description: "A dedicated RFC 6455 WebSocket endpoint handling its own upgrade handshake."
keywords: ["powpow", "example", "wsserver"]
---

# Standalone WebSocket server

A WebSocket-only server: `newWsServer()` performs the upgrade handshake internally, no HTTP routes involved. Callbacks cover the connection lifecycle and frame types.

Source: [`examples/wsserver.nim`](../../examples/wsserver.nim)

```nim
## examples/wsserver.nim — Standalone WebSocket server demo.
##
## A dedicated WebSocket server that handles the HTTP upgrade
## handshake internally. No HTTP routes needed — pure WebSocket.
##
## Run:
##   nim c -r examples/wsserver.nim
##
## Test with websocat:
##   websocat ws://localhost:9001
##
## Test with wscat:
##   npx wscat -c ws://localhost:9001

import ../src/powpow
import std/[httpcore, posix]

# ── Standalone WebSocket server ──────────────────────────────────────────────
#
# A dedicated WebSocket server that handles the HTTP upgrade
# handshake internally. No HTTP routes — pure WebSocket.

let wss = newWsServer()

var clientCount = 0

wss.onOpen do (ws: WsConnection):
  inc clientCount
  echo "⚡ WS client connected (fd=", ws.conn.fd.int,
       ", total=", clientCount, ")"
  ws.sendText("Welcome to powpow WebSocket!")

wss.onMessage do (ws: WsConnection, kind: WsFrameKind, data: openArray[byte]):
  let msg = cast[string](@data)
  case kind
  of wsText:
    echo "← text: ", msg
    # Echo back with prefix
    ws.sendText("echo: " & msg)
  of wsBinary:
    echo "← binary: ", data.len, " bytes"
    ws.sendBinary(data)  # echo back
  of wsPing:
    echo "← ping"
  of wsClose:
    echo "← close"
  else:
    discard

wss.onClose do (ws: WsConnection, code: int, reason: string):
  dec clientCount
  echo "⚡ WS client disconnected (code=", code,
       ", reason=\"", reason, "\", total=", clientCount, ")"

wss.onError do (ws: WsConnection, err: string):
  echo "⚠ WS error: ", err

wss.listen("0.0.0.0", 9001)
echo "⚡ Standalone WS server on ws://localhost:9001"
echo "  Press Ctrl+C to stop"

wss.start()
```

## Running

```bash
nim c -r examples/wsserver.nim
```

## Try it

```bash
websocat ws://localhost:9001
npx wscat -c ws://localhost:9001
```

## How it works

- `onOpen`, `onMessage`, `onClose`, `onError` register lifecycle callbacks; `onMessage` receives the frame kind plus payload.
- Text frames echo back prefixed; binary frames echo verbatim; pings are answered automatically by the protocol layer.
- `ws.sendText` / `ws.sendBinary` are safe to call from any callback.
- `handshakeCount()` reports in-flight upgrades when instrumenting handshake limits.

[WebSocket guide](../websocket.md) and [WebSocket API](../api/ws.md).

