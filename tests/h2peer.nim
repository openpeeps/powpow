## tests/h2peer.nim — shared in-loop H2 test peer (raw frames).
##
## Used by the HTTP/2 loopback suites (`test_http2`, `test_http2_security`).
## A peer speaks frames over `loop.connect` with flow-control accounting,
## HPACK contexts, and response collection. Not a test suite itself.

import ../src/powpow
import ../src/powpow/proto/[http2, hpack, http2conn]
import std/tables

const H2Magic* = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

type H2Peer* = ref object
  conn*: Connection
  parser*: H2FrameParser
  enc*: HpackContext
  dec*: HpackContext
  sendWindow*: int32
  streamSend*: Table[int32, int32]
  recvWindow*: int32
  streamRecv*: Table[int32, int32]
  respHeaders*: Table[int32, seq[HpackHeader]]
  respBody*: Table[int32, seq[byte]]
  respDone*: Table[int32, bool]
  streamReset*: Table[int32, bool]
  gotGoaway*: bool
  goawayCode*: H2ErrorCode
  pingAcked*: bool
  pingOpaque*: array[8, byte]
  queue*: seq[tuple[sid: int32, data: seq[byte], off: int, fin: bool]]
  onFrame*: proc(p: H2Peer, f: H2Frame) {.closure.}

proc newPeer*(conn: Connection): H2Peer =
  H2Peer(conn: conn, parser: newH2FrameParser(),
         enc: newHpackContext(), dec: newHpackContext(),
         sendWindow: 65535, streamSend: initTable[int32, int32](),
         recvWindow: 65535, streamRecv: initTable[int32, int32](),
         respHeaders: initTable[int32, seq[HpackHeader]](),
         respBody: initTable[int32, seq[byte]](),
         respDone: initTable[int32, bool](),
         streamReset: initTable[int32, bool](),
         queue: @[])

proc peerSend*(p: H2Peer, bytes: seq[byte]) =
  discard p.conn.send(bytes)

proc peerSendStr*(p: H2Peer, s: string) =
  var b = newSeq[byte](s.len)
  for i, c in s: b[i] = byte(c)
  p.peerSend(b)

proc peerHeaders*(p: H2Peer, sid: int32, meth, path: string,
                  endStream = true, endHeaders = true,
                  extra: seq[(string, string)] = @[]) =
  var hs = @[HpackHeader(name: ":method", value: meth),
             HpackHeader(name: ":scheme", value: "http"),
             HpackHeader(name: ":path", value: path),
             HpackHeader(name: ":authority", value: "127.0.0.1")]
  for (n, v) in extra:
    hs.add(HpackHeader(name: n, value: v))
  p.peerSend(encodeHeaders(sid, p.enc.encode(hs), endStream, endHeaders))
  p.streamSend[sid] = 65535
  p.streamRecv[sid] = 65535

proc peerBody*(p: H2Peer, sid: int32, body: seq[byte], fin = true) =
  var off = 0
  while off < body.len:
    let avail = min([p.sendWindow, p.streamSend.getOrDefault(sid, 65535),
                     int32(16384)])
    if avail <= 0:
      p.queue.add((sid, body, off, fin))
      return
    let n = min(avail, int32(body.len - off))
    let last = off + int(n) == body.len and fin
    var flags: uint8 = 0
    if last: flags = flags or H2FlagEndStream
    p.peerSend(encodeFrame(0, flags, sid,
      body.toOpenArray(off, off + int(n) - 1)))
    p.sendWindow -= n
    p.streamSend[sid] = p.streamSend.getOrDefault(sid, 65535) - n
    off += int(n)

proc peerTopUp(p: H2Peer, sid: int32) =
  if p.recvWindow < 32768:
    let inc = uint32(65535 - int(p.recvWindow))
    p.recvWindow = 65535
    p.peerSend(encodeWindowUpdate(0, inc))
  let w = p.streamRecv.getOrDefault(sid, 65535)
  if w < 32768:
    let inc = uint32(65535 - int(w))
    p.streamRecv[sid] = 65535
    p.peerSend(encodeWindowUpdate(sid, inc))

proc peerFeed*(p: H2Peer, data: openArray[byte]) =
  for f in p.parser.feed(data):
    if p.onFrame != nil:
      p.onFrame(p, f)
    case f.rawType
    of 4:  # SETTINGS
      if (f.flags and H2FlagAck) == 0:
        p.peerSend(encodeSettingsAck())
    of 1:  # HEADERS
      let hs = p.dec.decode(f.payload)
      if not p.respHeaders.hasKey(f.streamId):
        p.respHeaders[f.streamId] = @[]
      for h in hs: p.respHeaders[f.streamId].add(h)
      if (f.flags and H2FlagEndStream) != 0:
        p.respDone[f.streamId] = true
    of 0:  # DATA
      if not p.respBody.hasKey(f.streamId):
        p.respBody[f.streamId] = @[]
      for b in f.payload: p.respBody[f.streamId].add(b)
      p.recvWindow -= int32(f.payload.len)
      p.streamRecv[f.streamId] =
        p.streamRecv.getOrDefault(f.streamId, 65535) - int32(f.payload.len)
      p.peerTopUp(f.streamId)
      if (f.flags and H2FlagEndStream) != 0:
        p.respDone[f.streamId] = true
    of 8:  # WINDOW_UPDATE
      let inc = f.decodeWindowUpdate()
      if f.streamId == 0:
        p.sendWindow += int32(inc)
      else:
        p.streamSend[f.streamId] =
          p.streamSend.getOrDefault(f.streamId, 65535) + int32(inc)
      # Flush queued sends in order.
      while p.queue.len > 0:
        let (sid, data, off, fin) = p.queue[0]
        let avail = min([p.sendWindow, p.streamSend.getOrDefault(sid, 65535),
                         int32(16384)])
        if avail <= 0: break
        let n = min(avail, int32(data.len - off))
        let last = off + int(n) == data.len and fin
        var flags: uint8 = 0
        if last: flags = flags or H2FlagEndStream
        p.peerSend(encodeFrame(0, flags, sid,
          data.toOpenArray(off, off + int(n) - 1)))
        p.sendWindow -= n
        p.streamSend[sid] = p.streamSend.getOrDefault(sid, 65535) - n
        if off + int(n) >= data.len:
          p.queue.delete(0)
        else:
          p.queue[0] = (sid, data, off + int(n), fin)
          break
    of 6:  # PING
      if (f.flags and H2FlagAck) != 0:
        p.pingAcked = true
        p.pingOpaque = f.decodePing()
      else:
        p.peerSend(encodePingAck(f.decodePing()))
    of 7:  # GOAWAY
      let (_, code, _) = f.decodeGoaway()
      p.gotGoaway = true
      p.goawayCode = code
    of 3:  # RST_STREAM
      p.streamReset[f.streamId] = true
    else: discard

proc respStatus*(p: H2Peer, sid: int32): string =
  for h in p.respHeaders.getOrDefault(sid, @[]):
    if h.name == ":status": return h.value
  ""

proc respHeader*(p: H2Peer, sid: int32, name: string): string =
  for h in p.respHeaders.getOrDefault(sid, @[]):
    if h.name == name: return h.value
  ""

proc h2watchdog*(loop: Loop, srv: H2Server, ms = 8000) =
  discard loop.addTimer(ms) do (id: int):
    srv.close()
    loop.stop()
