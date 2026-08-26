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
