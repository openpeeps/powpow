## examples/tcp_client.nim — Interactive TCP client for tcp_chat.nim.
##
## Connects to the chat server and lets you type lines from stdin. Stdin is
## polled non-blockingly on the event loop, so incoming messages print while
## you are still typing.
##
## Run (after starting examples/tcp_chat.nim):
##   nim c -r examples/tcp_client.nim
##
## Type a line and hit Enter; messages from other clients are printed inline.

import ../src/powpow
import std/strutils
when not defined(windows):
  import std/posix

const Host = "127.0.0.1"
const Port = 9010

let loop = newLoop()

var conn: Connection
var outBuf: string = ""

proc sendLine(line: string) =
  if conn != nil:
    discard conn.send(line & "\n")

proc pumpStdin() =
  when not defined(windows):
    var chunk: array[4096, char]
    let n = posix.read(0, addr chunk[0], chunk.len)
    if n > 0:
      for i in 0 ..< n:
        outBuf.add(chunk[i])
    var lineEnd = outBuf.find('\n')
    while lineEnd >= 0:
      let line = outBuf[0 .. lineEnd].strip()
      outBuf = outBuf[lineEnd + 1 .. ^1]
      if line.len > 0:
        sendLine(line)
      lineEnd = outBuf.find('\n')

when not defined(windows):
  # Put stdin in non-blocking mode so the loop can poll it.
  var flags = fcntl(0, F_GETFL, 0)
  discard fcntl(0, F_SETFL, flags or O_NONBLOCK)

discard loop.addInterval(30) do (id: int):
  pumpStdin()

loop.connect(Host, Port,
  onConnect = proc(c: Connection) =
    conn = c
    echo "⚡ connected to ", Host, ":", Port, " — type a message and press Enter"
  ,
  onData = proc(c: Connection, data: openArray[byte]) =
    echo "  ← ", $cast[string](@data)
  ,
  onClose = proc(c: Connection) =
    echo "⚡ disconnected"
    loop.stop()
  ,
)

# Safety timeout: exit after 10 minutes if still connected.
discard loop.addTimer(600_000) do (id: int):
  loop.stop()

loop.run()
