## examples/signal_bus.nim — In-process pub/sub event bus (SignalRelay).
##
## Demonstrates powpow's signal/relay system: an HTTP endpoint emits named
## events on the event loop and subscribers react to them. Also shows
## `listenOnce` (auto-unsubscribes after the first event) and `unlisten`.
##
## Run:
##   nim c -r examples/signal_bus.nim
##
## Test:
##   curl "http://localhost:9005/emit?signal=1"     # permanent subscriber
##   curl "http://localhost:9005/emit?signal=3"     # once-subscriber (then gone)
##   curl "http://localhost:9005/emit?signal=3"     # nobody listening anymore

import ../src/powpow
import std/[httpcore, strutils]

const SignalPort = 9005
const SignalCount = 8

let loop = newLoop()
let server = newHttpServer(loop)
let relay = newSignalRelay(loop, SignalCount)

# Permanent subscribers.
discard relay.listen(1) do ():
  echo "⚡ event #1 received"
discard relay.listen(2) do ():
  echo "⚡ event #2 received"

# A once-only subscriber — unsubscribes after the first event.
discard relay.listenOnce(3) do ():
  echo "⚡ event #3 received (once-only listener, now unsubscribed)"

# A subscriber we will explicitly unsubscribe after the first event.
var counter = 0
var listener: ListenerHandle
listener = relay.listen(4) do ():
  inc counter
  echo "⚡ event #4 received (count=", $counter, ")"
  if counter >= 2:
    listener.unlisten()
    echo "  → unlistened from event #4"

server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  {.gcsafe.}:
    let path = req.getPath()
    if path == "/emit":
      let query = req.getQuery()
      let sigStr = query.split("signal=")
      var signal = 0
      if sigStr.len == 2:
        signal = try: parseInt(sigStr[1]) except ValueError: 0
      if signal > 0 and signal < SignalCount:
        relay.emit(signal)
        res.status(Http200)
          .header("Content-Type", "text/plain; charset=utf-8")
          .send("emitted signal " & $signal)
      else:
        res.sendError(Http400, "use ?signal=1.." & $(SignalCount - 1))
    else:
      res.sendError(Http404, "404 Not Found: " & path)

echo "⚡ signal bus listening on http://localhost:" & $SignalPort
echo "  Emit events with:  curl \"http://localhost:" & $SignalPort & "/emit?signal=1\""
echo "  Press Ctrl+C to stop"
server.start(server.handler, Port(SignalPort))
