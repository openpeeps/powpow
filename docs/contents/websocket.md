---
title: WebSocket
description: "RFC 6455 WebSocket in powpow: standalone servers, HTTP-upgrade endpoints, and a self-managed client with auto-reconnect, wss:// support and sendMessage."
keywords: ["powpow", "websocket", "ws", "wss", "realtime", "client"]
---

# WebSocket

`proto/ws.nim` is an RFC 6455-compliant WebSocket implementation with a
server side in two modes plus a first-class client:

1. **Standalone server**: a dedicated WebSocket server that handles the
   upgrade handshake internally (no HTTP routes).
2. **Upgrade**: a WebSocket endpoint on an existing `HttpServer` route, so
   HTTP and WebSocket share one port.
3. **Client**: connect out to any RFC 6455 endpoint with `newWsClient()`
   (high level, auto-reconnect, own loop) or `connectWs()` (low level, your
   loop).

Runnable examples: [`examples/wsserver.nim`](../examples/wsserver.nim),
[`examples/wsupgrade.nim`](../examples/wsupgrade.nim),
[`examples/ws_chat.nim`](../examples/ws_chat.nim),
[`examples/wsclient.nim`](../examples/wsclient.nim).

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

## Sending messages

Both session flavors share one high-level send API. The argument type picks
the framing:

```nim
ws.sendMessage("hello")          # text frame
ws.sendMessage(@[1.byte, 2, 3])  # binary frame
```

Explicit variants remain available for control cases:
`sendText`, `sendBinary`, `sendPing`, `sendPong`,
`closeWs(code = 1000, reason = "")`.

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
    discard websocketUpgrade(res, req,
      protocols = ["chat.v2"],       # subprotocols this endpoint supports
      onMessage = proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
        ws.sendText("echo: " & cast[string](data)))
  else:
    res.send("<h1>HTTP on the same port</h1>")

let server = newHttpServer()
server.start(handler, Port(9000))
```

When the client offers subprotocols, the first match in client preference
order is selected and echoed back as `Sec-WebSocket-Protocol`.

## Client (high level)

`newWsClient()` mirrors `newWsServer()`: it creates and owns its private
event loop, exposes setter-style callbacks that survive reconnects, and runs
until closed.

```nim
let client = newWsClient(WsReconnectPolicy(
  maxRetries: 5,          # -1 = unlimited
  backoffStartMs: 250,    # exponential backoff with jitter between retries
  backoffMaxMs: 4_000))

client.onOpen do (ws: WsConnection):
  ws.sendMessage("hello")

client.onMessage do (ws: WsConnection, kind: WsFrameKind,
                     data: openArray[byte]):
  echo kind, ": ", cast[string](@data)

client.onClose do (ws: WsConnection, code: int, reason: string):
  echo "closed ", code

client.onRetry do (attempt: int, delayMs: int):
  echo "retrying in ", delayMs, " ms"

client.onGiveUp do (attempts: int):
  echo "giving up after ", attempts, " attempts"

discard client.connect("ws://127.0.0.1:9001")
client.run()        # blocks; returns after close() or give-up
```

Behavior details:

- **Auto-reconnect** fires on failed handshakes and abnormal drops (code
  1006). Deliberate closes never trigger it; `client.close(code, reason)`
  tears down the session and stops the loop so a blocked `run()` returns.
- **wss://** works out of the box: a verifying TLS context is created
  automatically from the URL scheme, or supply your own via
  `setTlsContext()` (for example `verifyPeer = false` against self-signed
  servers).
- **Custom handshake headers** travel with `connect(url,
  headers = [("Authorization", "Bearer ...")])`.
- **Subprotocols** are offered via `connect(url, protocols = ["chat.v2"])`;
  after the handshake, `ws.getProtocol()` reports the server's pick.
- **Keepalive knobs**: `pingIntervalMs` sends periodic pings once open;
  `idleTimeoutMs` closes sessions that receive nothing for that long
  (surfacing dead NAT connections as code 1001).

## Client (low level)

For code that already owns a loop, `connectWs` dials and handshakes without
any facade, returning the raw `WsConnection` immediately:

```nim
let ws = connectWs(loop, "127.0.0.1", 9001, "/",
  onOpen = proc(ws: WsConnection) = ws.sendMessage("hi"),
  onMessage = proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
    discard,
  onClose = proc(ws: WsConnection, code: int, reason: string) = discard)
# then run `loop` yourself
```

`upgradeToWs(conn, path, host)` upgrades an already-connected plaintext TCP
connection instead of dialing. URL parsing helper:
`parseWsUrl("wss://host:443/path?x")` splits scheme, host, port and path
(raising `WsError` on malformed input). Both procs accept the same optional
parameters as the high-level client (`extraHeaders`, `protocols`,
`pingIntervalMs`, `idleTimeoutMs`, `tlsCtx` on `connectWs`).

## Configuration & limits

`WsServer` public fields:

| Field | Purpose |
|---|---|
| `maxFrameSize` | max frame payload (`DefaultMaxFrameSize` = 10 MB) |
| `handshakeTimeoutMs` | close upgrades that never finish the handshake |
| `maxHandshakeSessions` | cap in-flight handshakes (stall-DoS defense) |
| `idleTimeoutMs` | post-upgrade idle close |

Per-message deflate is supported. Frame caps still apply in
`maxFrameSize = 0` ("unlimited") mode, see [security](security.md).

## Related

[HTTP server guide](http/server.md), the runnable
[wsclient example](examples/wsclient.md), and the generated
[API reference](https://openpeeps.github.io/powpow) for full signatures.
