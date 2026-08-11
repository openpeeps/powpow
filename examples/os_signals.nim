# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## examples/os_signals.nim — Graceful shutdown via OS signals.
##
## Demonstrates the classic server shutdown flow: SIGINT/SIGTERM are delivered
## through the event loop (no global signal handlers), the handler stops the
## loop, and the server is closed cleanly afterwards.
##
## Run:
##   nim c -r examples/os_signals.nim
##
## Then press Ctrl+C (SIGINT) or send SIGTERM:
##   kill -TERM <pid>

import ../src/powpow
import std/[httpcore]

let loop = newLoop()
let server = newHttpServer(loop)
let relay = newOsSignalRelay(loop)

server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  {.cast(gcsafe).}:
    res.status(Http200)
       .header("Content-Type", "text/plain; charset=utf-8")
       .send("powpow running — press Ctrl+C to stop")

# Clean shutdown on SIGINT (Ctrl+C) and SIGTERM.
discard relay.listen(SignalInt) do ():
  echo "\n⚡ SIGINT received — shutting down"
  loop.stop()
discard relay.listen(SignalTerm) do ():
  echo "\n⚡ SIGTERM received — shutting down"
  loop.stop()

# Also demonstrate SIGHUP as a "reload" signal.
discard relay.listen(SignalHup) do ():
  echo "⚡ SIGHUP received — reloading"

relay.watchOsSignals([SignalInt, SignalTerm, SignalHup])

server.listen("127.0.0.1", 9007)
echo "powpow listening on http://127.0.0.1:9007 — press Ctrl+C or send SIGTERM/SIGHUP"

loop.run()

# After the loop stops (signal handler), close everything cleanly.
server.close()
loop.close()
echo "bye"
