## tests/test_net.nim — Tests for the powpow transport layer.
##
## Tests: TCP server echo, TCP client connect, UDP bind/send/recv.

import ../src/powpow
import std/[posix, os, unittest]

# ── Test 1: TCP echo server ──────────────────────────────────────────────────

test "test_tcp_echo":
  var received: seq[byte] = @[]
  var clientConnected = false
  var clientReceived: seq[byte] = @[]
  var serverDone = false

  let loop = newLoop()

  # Create server
  let server = newTcpServer(loop,
    onAccept = proc(conn: Connection) =
      discard  # accepted
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      # Echo back
      let sent = conn.send(data)
      doAssert sent == data.len, "server echo send failed"
    ,
  )
  server.listen("127.0.0.1", 19876)

  # After a short delay, connect a client
  discard loop.addTimer(50) do (id: int):
    loop.connect("127.0.0.1", 19876,
      onConnect = proc(conn: Connection) =
        clientConnected = true
        discard conn.send("hello powpow")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        clientReceived = @data
        conn.close()
        server.close()
        serverDone = true
        loop.stop()
      ,
    )

  # Safety timeout — don't hang forever
  discard loop.addTimer(3000) do (id: int):
    server.close()
    serverDone = true
    loop.stop()

  loop.run()

  doAssert clientConnected, "client should have connected"
  doAssert clientReceived.len > 0, "client should have received echo"
  doAssert cast[string](clientReceived) == "hello powpow",
    "echo mismatch: " & cast[string](clientReceived)
  loop.close()

# ── Test 2: TCP server close callback ────────────────────────────────────────

test "test_tcp_close":
  var serverClosed = false
  let loop = newLoop()
  var server: TcpServer
  server = newTcpServer(loop,
    onAccept = proc(conn: Connection) = discard,
    onData = proc(conn: Connection, data: openArray[byte]) =
      # Just close immediately
      conn.close()
    ,
    onClose = proc(conn: Connection) =
      serverClosed = true
      server.close()
      loop.stop()
    ,
  )
  server.listen("127.0.0.1", 19877)

  discard loop.addTimer(50) do (id: int):
    loop.connect("127.0.0.1", 19877,
      onConnect = proc(conn: Connection) =
        discard conn.send("close me")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        discard
      ,
    )

  discard loop.addTimer(3000) do (id: int):
    server.close()
    loop.stop()

  loop.run()

  doAssert serverClosed, "onClose should have fired"
  loop.close()

# ── Test 3: UDP send/recv ────────────────────────────────────────────────────

test "test_udp":
  var gotMsg = false
  var recvData: seq[byte] = @[]
  let loop = newLoop()

  # Bind a UDP listener
  var server: UdpSocket
  server = loop.bindUdp("127.0.0.1", 19878,
    onData = proc(msg: UdpMessage) =
      recvData = msg.data
      gotMsg = true
      server.close()
      loop.stop()
  )

  # Send a datagram after a short delay
  discard loop.addTimer(50) do (id: int):
    let sender = loop.connectUdp("127.0.0.1", 19878)
    discard sender.send("yo powpow")
    sender.close()

  # Safety timeout
  discard loop.addTimer(3000) do (id: int):
    server.close()
    loop.stop()

  loop.run()

  doAssert gotMsg, "UDP listener should have received a datagram"
  doAssert cast[string](recvData) == "yo powpow",
    "UDP data mismatch: " & cast[string](recvData)
  loop.close()

