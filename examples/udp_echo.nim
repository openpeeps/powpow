## examples/udp_echo.nim — UDP echo server + bundled ping client.
##
## Demonstrates powpow's UDP layer: a bound `UdpSocket` that receives datagrams
## via `onData` (with the sender's address) and echoes them back with `sendTo`,
## plus a `--client` mode that pings the server with `connectUdp`.
##
## Run (server):
##   nim c -r examples/udp_echo.nim
##
## Test with the built-in client (another terminal):
##   nim c -r examples/udp_echo.nim -- --client
##
## Or with netcat:
##   echo "hello udp" | nc -u -w1 127.0.0.1 9011

import ../src/powpow
import std/[strutils, os]

const Host = "127.0.0.1"
const Port = 9011

proc senderAddr(sa: Sockaddr_storage): tuple[ip: string; port: int] =
  ## Format a `Sockaddr_storage` into "ip:port" using getnameinfo (numeric).
  const NI_MAXHOST = 1025
  const NI_NUMERICHOST = 1
  const NI_NUMERICSERV = 2
  var host: array[NI_MAXHOST, char]
  var serv: array[16, char]
  let saPtr = cast[ptr Sockaddr](unsafeAddr sa)
  let saLen = getSockLen(unsafeAddr sa)
  when defined(windows):
    if getnameinfo(saPtr, saLen, cast[cstring](addr host[0]), NI_MAXHOST.DWORD,
                   cast[cstring](addr serv[0]), 16.DWORD,
                   NI_NUMERICHOST or NI_NUMERICSERV) == 0:
      result = ($cast[cstring](addr host[0]),
                try: parseInt($cast[cstring](addr serv[0])) except ValueError: 0)
  else:
    if getnameinfo(saPtr, saLen, cast[cstring](addr host[0]), host.len.SockLen,
                   cast[cstring](addr serv[0]), serv.len.SockLen,
                   NI_NUMERICHOST or NI_NUMERICSERV) == 0:
      result = ($cast[cstring](addr host[0]),
                try: parseInt($cast[cstring](addr serv[0])) except ValueError: 0)
    else:
      result = ("unknown", 0)

proc runServer() =
  let loop = newLoop()
  var server: UdpSocket
  server = loop.bindUdp("0.0.0.0", Port,
    onData = proc(sender: Sockaddr_storage; data: openArray[byte]) =
      let fromAddr = senderAddr(sender)
      let text = $cast[string](@data)
      echo "← ", fromAddr.ip, ":", fromAddr.port, " says: ", text
      let n = server.sendTo(text, fromAddr.ip, fromAddr.port)
      echo "→ echoed ", n, " bytes"
  )
  echo "⚡ UDP echo server listening on 0.0.0.0:" & $Port
  echo "  Ping it with:   nim c -r examples/udp_echo.nim -- --client"
  echo "  Press Ctrl+C to stop"
  loop.run()

proc runClient() =
  let loop = newLoop()
  let sock = loop.connectUdp(Host, Port,
    onData = proc(sender: Sockaddr_storage; data: openArray[byte]) =
      echo "→ echo reply: ", $cast[string](@data)
  )
  echo "⚡ UDP client connected to ", Host, ":", Port, " — sending a ping"
  discard sock.send("ping from powpow!")
  discard loop.addTimer(2000) do (id: int):
    sock.close()
    loop.stop()
  loop.run()

if paramCount() > 0 and paramStr(1) == "--client":
  runClient()
else:
  runServer()
