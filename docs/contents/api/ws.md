---
title: ws
description: "The WebSocket API: WsServer, WsConnection, frames, callbacks and websocketUpgrade."
keywords: ["powpow", "api", "websocket", "ws", "frames"]
---

# ws

RFC 6455 WebSocket server (standalone or HTTP-upgrade path).
Source: `src/powpow/proto/ws.nim`. Guide: [WebSocket](../websocket.md).

## Constant

```nim
DefaultMaxFrameSize* = 10 * 1024 * 1024
```

## Enum

```nim
WsFrameKind* = enum
  wsContinuation = 0x0
  wsText = 0x1
  wsBinary = 0x2
  wsClose = 0x8
  wsPing = 0x9
  wsPong = 0xA
```

## Types

```nim
WsConnection* = ref object
  conn*: Connection
  onMessage*: WsMessageCb
  onClose*: WsCloseCb
  onError*: WsErrorCb
  onOpen*: WsOpenCb
  maxFrameSize*: int

WsMessageCb* = proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) {.closure.}
WsCloseCb*   = proc(ws: WsConnection, code: int, reason: string) {.closure.}
WsErrorCb*   = proc(ws: WsConnection, err: string) {.closure.}
WsOpenCb*    = proc(ws: WsConnection) {.closure.}

WsServer* = ref object
  maxFrameSize*: int
  handshakeTimeoutMs*: int
  idleTimeoutMs*: int
  maxHandshakeSessions*: int
```

## Server procs

```nim
proc newWsServer*(loop: Loop; maxFrameSize: int = DefaultMaxFrameSize): WsServer
proc newWsServer*(maxFrameSize: int = DefaultMaxFrameSize): WsServer    # own loop
proc start*(wss: WsServer)
proc onOpen*(wss: WsServer, cb: WsOpenCb)
proc onMessage*(wss: WsServer, cb: WsMessageCb)
proc onClose*(wss: WsServer, cb: WsCloseCb)
proc onError*(wss: WsServer, cb: WsErrorCb)
proc handshakeCount*(wss: WsServer): int {.inline.}
proc listen*(wss: WsServer, address: string, port: int)
proc close*(wss: WsServer)
```

## Connection / frame procs

```nim
proc sendText*(ws: WsConnection, s: string) {.inline.}
proc sendBinary*(ws: WsConnection, data: openArray[byte]) {.inline.}
proc sendPing*(ws: WsConnection, data: openArray[byte] = []) {.inline.}
proc sendPong*(ws: WsConnection, data: openArray[byte] = []) {.inline.}
proc closeWs*(ws: WsConnection, code: int = 1000, reason: string = "")
proc parseWsFrames*(ws: WsConnection, data: openArray[byte])
proc newWsConnection*(conn: Connection; maxFrameSize: int = DefaultMaxFrameSize): WsConnection

# low-level helpers
func computeAcceptKey*(clientKey: string): string
proc buildHandshakeResponse*(acceptKey: string): string
proc sendHandshake*(conn: Connection, clientKey: string) {.inline.}
proc writeFrame*(conn: Connection, opcode: int, payload: openArray[byte])
proc writeFrameMasked*(conn: Connection, opcode: int, payload: openArray[byte], mask: array[4, uint8])
proc reset*(p: WsFrameParser)
```

## HTTP upgrade

```nim
proc websocketUpgrade*(res: HttpResponse, req: HttpRequest,
                       server: HttpServer = nil,
                       onOpen: WsOpenCb = nil,
                       onMessage: WsMessageCb = nil,
                       onClose: WsCloseCb = nil,
                       onError: WsErrorCb = nil,
                       maxFrameSize: int = DefaultMaxFrameSize): WsConnection {.gcsafe, discardable.}
```

## Related

- [httpserver](httpserver.md) — upgrade path
- [security](../security.md) — frame and handshake caps
