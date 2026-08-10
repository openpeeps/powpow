## audit/ws_idle_timeout.nim
##
## Round-2: an upgraded WebSocket connection that sends no frames within
## idleTimeoutMs must be closed (previously it held the connection + fd
## forever); sending frames must keep it alive.

import powpow
import std/[httpcore, unittest]

proc makeMaskedFrame(opcode: int; payload: seq[byte]): seq[byte] =
  result.add(uint8(0x80 or (opcode and 0x0F)))
  let mask = [0x11'u8, 0x22, 0x33, 0x44]
  if payload.len < 126:
    result.add(uint8(0x80 or payload.len))
  else:
    result.add(uint8(0x80 or 126))
    result.add(uint8((payload.len shr 8) and 0xFF))
    result.add(uint8(payload.len and 0xFF))
  for m in mask: result.add(m)
  for i, b in payload: result.add(b xor mask[i mod 4])

suite "websocket post-upgrade idle timeout":

  test "silent upgraded connection is closed by idleTimeoutMs":
    let loop = newLoop()
    var wss = newWsServer(loop)
    wss.handshakeTimeoutMs = 2000
    wss.idleTimeoutMs = 120
    wss.listen("127.0.0.1", 29962)
    var opened = false
    var closed = false
    loop.connect("127.0.0.1", 29962,
      onConnect = proc(conn: Connection) =
        discard conn.send("GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n" &
                          "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" &
                          "Sec-WebSocket-Version: 13\r\n\r\n")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) = opened = true,
      onClose = proc(conn: Connection) = closed = true,
    )
    var polls = 0
    while not closed and polls < 10000:
      loop.poll(1)
      inc polls
    check opened
    check closed
    doAssert polls < 1500, "closed by idle (120ms), not handshake timeout (2000ms): " & $polls
    wss.close()
    loop.close()

  test "traffic keeps the connection open; silence closes it":
    let loop = newLoop()
    var wss = newWsServer(loop)
    wss.handshakeTimeoutMs = 2000
    wss.idleTimeoutMs = 150
    wss.listen("127.0.0.1", 29963)
    var clientConn: Connection = nil
    var opened = false
    var closed = false
    var trafficTimer: TimerId
    loop.connect("127.0.0.1", 29963,
      onConnect = proc(conn: Connection) =
        clientConn = conn
        discard conn.send("GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n" &
                          "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" &
                          "Sec-WebSocket-Version: 13\r\n\r\n")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        if not opened:
          opened = true
          trafficTimer = loop.addInterval(40) do (id: int):
            if clientConn != nil and clientConn.state == Connected:
              discard clientConn.send(makeMaskedFrame(0x9, @[0x00'u8]))
      ,
      onClose = proc(conn: Connection) = closed = true,
    )
    var polls = 0
    while polls < 400 and not closed:
      loop.poll(1)
      inc polls
    check opened
    doAssert not closed, "must stay open while frames arrive"
    if trafficTimer != TimerId(0):
      loop.cancelTimer(trafficTimer)
    while not closed and polls < 10000:
      loop.poll(1)
      inc polls
    doAssert closed, "must close once traffic stops"
    if clientConn != nil: clientConn.close()
    wss.close()
    loop.close()
