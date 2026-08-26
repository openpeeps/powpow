---
title: WebSocket client
description: "High-level newWsClient: self-owned loop, auto-reconnect with backoff, sendMessage dispatch, wss:// support."
keywords: ["powpow", "example", "wsclient", "websocket", "client", "reconnect"]
---

# WebSocket client

The high-level client in action: `newWsClient()` creates and owns its event
loop, callbacks survive reconnects, and `sendMessage` dispatches strings as
text frames and byte sequences as binary frames. The reconnect policy gives
up after five consecutive failures, so pointing it at a dead port produces a
clean "gave up" instead of an infinite loop.

Source: [`examples/wsclient.nim`](../../examples/wsclient.nim)

```nim
## examples/wsclient.nim — WebSocket client demo (high-level + low-level).
##
## Connects to examples/wsserver.nim (port 9001) with the high-level
## `newWsClient` facade: self-owned loop, auto-reconnect on abnormal drops,
## and `sendMessage` dispatching strings as text frames, byte sequences as
## binary frames.
##
## Run (after starting examples/wsserver.nim):
##   nim c -r examples/wsclient.nim
##
## The client works against any RFC 6455 server, e.g.:
##   websocat -E ws://localhost:9001
##
## Low-level alternative: connectWs(loop, host, port, ...) returns a raw
## WsConnection on YOUR loop (see docs/websocket.md for both flavors).

import ../src/powpow
import std/strutils

const Url = "ws://127.0.0.1:9001"

let client = newWsClient(WsReconnectPolicy(
  maxRetries: 5,          # give up after 5 consecutive failed attempts
  backoffStartMs: 250,
  backoffMaxMs: 4_000,
  jitter: 0.2))

client.onOpen do (ws: WsConnection):
  echo "connected to ", Url
  ws.sendMessage("Hello from powpow WS client!")   # text frame
  ws.sendMessage(@[1.byte, 2, 3])                  # binary frame

client.onMessage do (ws: WsConnection, kind: WsFrameKind,
                     data: openArray[byte]):
  var done = false
  case kind
  of wsText:
    let msg = cast[string](@data)
    echo "text: ", msg
    done = msg.startsWith("echo:")
  of wsBinary:
    # Sent last, so its echo means the conversation is complete.
    echo "binary: ", data.len, " bytes"
    done = true
  else:
    discard
  if done and client.isConnected():
    ws.closeWs(1000, "bye")

client.onClose do (ws: WsConnection, code: int, reason: string):
  echo "closed (code=", code, ", reason=\"", reason, "\")"
  # Without this the client would sit in run() waiting to reconnect.
  # Abnormal drops (1006) bypass this branch and auto-reconnect instead.
  if code != 1006:
    client.close()

client.onError do (ws: WsConnection, err: string):
  echo "error: ", err

client.onRetry do (attempt: int, delayMs: int):
  echo "reconnecting in ", delayMs, " ms (attempt ", attempt, ")"

client.onGiveUp do (attempts: int):
  echo "gave up after ", attempts, " attempts; is the server running?"

# wss:// would be just as simple:
#   discard client.connect("wss://example.com/chat",
#                          headers = [("Authorization", "Bearer ...")])
if not client.connect(Url):
  quit("client busy")

client.run()   # blocks until close() or the policy gives up
echo "done"
```

## Running

```bash
nim c -r examples/wsserver.nim      # target server on ws://localhost:9001
nim c -r examples/wsclient.nim
```

## Try it

```bash
# happy path (with server running): connect, echo, clean close
nim c -r examples/wsclient.nim

# resilience: no server -> retries with exponential backoff, then give-up
websocat -E ws://localhost:9001 &   # or kill it mid-session to see 1006 recovery
```

## How it works

- `newWsClient(WsReconnectPolicy(maxRetries: 5, backoffStartMs: 250,
  backoffMaxMs: 4_000, jitter: 0.2))` builds the client; the constructor
  creates its private loop internally, mirroring `newWsServer()`.
- Setter callbacks (`onOpen`, `onMessage`, `onClose`, `onError`, `onRetry`,
  `onGiveUp`) persist across sessions; reconnection swaps only the inner
  connection object.
- `ws.sendMessage("...")` emits a text frame; `ws.sendMessage(seq[byte])`
  emits a binary frame. Explicit `sendText`/`sendBinary`/`sendPing` remain
  available for control cases.
- Abnormal drops arrive as code 1006 and are retried automatically;
  deliberate `closeWs(1000, ...)` never is. The example's `onClose` calls
  `client.close()` for clean closes so `run()` returns.
- wss:// is a one-liner away: `client.connect("wss://host/path",
  headers = [("Authorization", "Bearer x")])`. A verifying TLS context is
  created from the URL scheme automatically.
- Low-level alternative: `connectWs(loop, host, port, path, ...)`
  handshakes on YOUR loop; `upgradeToWs(conn, path, host)` upgrades an
  existing TCP connection.

Related: [WebSocket guide](../websocket.md) and the standalone
[wsserver example](wsserver.md).
