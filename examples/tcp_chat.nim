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
