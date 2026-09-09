# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/proto/http2conn.nim — HTTP/2 connection state machine + h2c server.
##
## Shared `H2Conn` framing core (RFC 7540 §5–§6) with a server role (this
## milestone) and room for the client role (M4): connection preface,
## SETTINGS exchange, stream lifecycle, HPACK block reassembly across
## CONTINUATION, receive/send flow control, and GOAWAY draining.
##
## `H2Server` serves cleartext (h2c) with prior knowledge (§3.4) and
## `Upgrade: h2c` (§3.2) on one port, or `h2` over TLS (ALPN) when built
## with `sslCtx`. The TLS port is h2-only: other ALPN outcomes are closed.
## Handler API is H2-native (`H2Request`/`H2Response`); sharing the H1
## `OnRequestCallback` is M5 work.
##
## Deliberate M2 simplifications, all documented at the call site:
## - Full request bodies are buffered (no streaming); oversize bodies are
##   refused with RST_STREAM(CANCEL).
## - PRIORITY is validated and ignored (no scheduling).
## - PUSH_PROMISE is a connection error (push deferred).
## - No per-stream timers; lifetime is bound to the TCP connection.

import std/[tables, strutils, sequtils, base64]

import ../net/tcp
import ../net/tls
import ../loop
import ./http2
import ./hpack

type
  H2Role* = enum
    H2ServerRole, H2ClientRole

  H2StreamState* = enum
    HsOpen, HsHalfClosedRemote, HsHalfClosedLocal, HsClosed

  H2Stream* = ref object
    id*: int32
    state*: H2StreamState
    reqHeaders*: seq[HpackHeader]
    reqBody*: seq[byte]
    respHeaders*: seq[HpackHeader]
    respBody*: seq[byte]
    clientCb*: H2ClientCallback
    recvWindow*: int32
    sendWindow*: int32

  H2ClientResponse* = object
    ## A complete response as delivered to `H2ClientCallback`.
    status*: int
    headers*: seq[(string, string)]
    body*: seq[byte]

  H2ClientCallback* = proc(resp: H2ClientResponse,
                           err: string) {.closure.}
    ## `err == ""` on success. Errors: `"reset by peer"`, `"refused"`,
    ## `"goaway"`, `"closed"`, `"protocol error"`. Plain `closure` (like
    ## the TCP layer) so callers may capture locals.

  H2Request* = object
    streamId*: int32
    meth*: string
    path*: string
    scheme*: string
    authority*: string
    headers*: seq[(string, string)]
    body*: seq[byte]

  H2Response* = ref object
    h2*: H2Conn
    streamId*: int32
    status*: uint16
    headers*: seq[(string, string)]
    sent*: bool

  OnH2RequestCallback* = proc(req: H2Request,
                              res: H2Response) {.closure, gcsafe.}

  H2PendingWrite = object
    sid: int32
    data: seq[byte]
    offset: int
    endStream: bool

  H2ConnState = enum
    CsSniff, CsPreface, CsReady, CsDraining, CsClosed

  H2Conn* = ref object
    conn*: Connection
    role*: H2Role
    state*: H2ConnState
    parser*: H2FrameParser
    encCtx*: HpackContext
    decCtx*: HpackContext
    streams*: Table[int32, H2Stream]
    sniffBuf*: seq[byte]
    fragStream*: int32   ## Stream with an open HEADERS block, -1 when none.
    fragBuf*: seq[byte]
    fragEndStream*: bool ## The opening HEADERS carried END_STREAM.
    prefaceSettingsSeen*: bool
    lastPeerSid*: int32
    openCount*: int
    recvWindow*: int32
    sendWindow*: int32
    peerInitWindow*: int32
    peerMaxFrame*: int
    peerMaxConcurrent*: int
    nextStreamId*: int32
    maxConcurrentLocal*: int
    maxHeaderList*: int
    maxBody*: int
    peerAckedSettings*: bool
    goawayReceived*: bool
    goawaySent*: bool
    pending*: seq[H2PendingWrite]
    onRequest*: OnH2RequestCallback
    onSettingsApplied*: proc(h2: H2Conn) {.closure.}
    alpnChecked*: bool

  H2Server* = ref object
    loop*: Loop
    tcp*: TcpServer
    handler*: OnH2RequestCallback
    sslCtx*: SslContext
    conns*: Table[int, H2Conn]
    maxConcurrent*: int
    maxHeaderList*: int
    maxBody*: int

const
  H2ConnMagic = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  H2UpgradeMethods = ["GET ", "POST ", "PUT ", "HEAD ", "OPTIONS ", "DELETE ",
                      "PATCH ", "CONNECT ", "TRACE "]
  H2DefaultMaxConcurrent* = 128
  H2DefaultMaxHeaderList* = 16 * 1024
  H2DefaultMaxBody* = 8 * 1024 * 1024
  H2WindowTopUpAt = 32768
  H2SniffCap = 8192

# ── Connection / stream teardown ────────────────────────────────────

proc connError(h2: H2Conn, code: H2ErrorCode) =
  ## Connection error: GOAWAY + TCP close. Idempotent.
  if h2.state == CsClosed:
    return
  h2.state = CsClosed
  if not h2.goawaySent:
    h2.goawaySent = true
    discard h2.conn.send(encodeGoaway(h2.lastPeerSid, code))
  h2.conn.close()
  h2.state = CsClosed
  if not h2.goawaySent:
    h2.goawaySent = true
    discard h2.conn.send(encodeGoaway(h2.lastPeerSid, code))
  h2.conn.close()

proc maybeDrain(h2: H2Conn) =
  ## After our peer asked to go away, close once in-flight streams finish.
  if h2.goawayReceived and h2.openCount <= 0 and not h2.goawaySent:
    h2.goawaySent = true
    if h2.state != CsClosed:
      discard h2.conn.send(encodeGoaway(h2.lastPeerSid, H2NoError))
    h2.state = CsClosed
    h2.conn.close()

proc streamError(h2: H2Conn, sid: int32, code: H2ErrorCode) =
  ## Stream error: RST_STREAM + drop stream state.
  if h2.streams.hasKey(sid):
    h2.streams.del(sid)
    dec h2.openCount
  if h2.state != CsClosed:
    discard h2.conn.send(encodeRstStream(sid, code))
  h2.maybeDrain()

proc closeStream(h2: H2Conn, sid: int32) =
  if h2.streams.hasKey(sid):
    h2.streams.del(sid)
    dec h2.openCount
  h2.maybeDrain()

proc sendWindowUpdate(h2: H2Conn, sid: int32, increment: uint32) =
  discard h2.conn.send(encodeWindowUpdate(sid, increment))

proc topUpRecv(h2: H2Conn, sid: int32, stream: H2Stream) =
  ## Restore connection- and stream-level receive windows past the
  ## threshold so well-behaved senders never stall.
  if h2.recvWindow < H2WindowTopUpAt:
    let inc = uint32(H2DefaultWindowSize - int(h2.recvWindow))
    h2.recvWindow = H2DefaultWindowSize
    h2.sendWindowUpdate(0, inc)
  if stream.recvWindow < H2WindowTopUpAt:
    let inc = uint32(H2DefaultWindowSize - int(stream.recvWindow))
    stream.recvWindow = H2DefaultWindowSize
    h2.sendWindowUpdate(sid, inc)

# ── SETTINGS ──────────────────────────────────────────────────────────

proc applyPeerSettings(h2: H2Conn, settings: seq[H2Setting]) =
  for s in settings:
    case int(s.id)
    of 1:  # HEADER_TABLE_SIZE: caps our encoder.
      h2.encCtx.maxAllowedSize = int(s.value)
      if h2.encCtx.maxTableSize > int(s.value):
        h2.encCtx.setMaxTableSize(int(s.value))
    of 2:  # ENABLE_PUSH: accepted and ignored (push deferred).
      discard
    of 3:  # MAX_CONCURRENT_STREAMS: caps streams a client may open.
      h2.peerMaxConcurrent = int(s.value)
    of 4:  # INITIAL_WINDOW_SIZE.
      if s.value > uint32(H2MaxWindowSize):
        h2.connError(H2FlowControlError)
        return
      let delta = int(s.value) - int(h2.peerInitWindow)
      h2.peerInitWindow = int32(s.value)
      for _, st in h2.streams.mpairs:
        if st.state == HsOpen or st.state == HsHalfClosedRemote:
          let w = int64(st.sendWindow) + int64(delta)
          if w > int64(H2MaxWindowSize):
            h2.connError(H2FlowControlError)
            return
          st.sendWindow = int32(w)
    of 5:  # MAX_FRAME_SIZE.
      if s.value < uint32(H2MaxFrameSizeMin) or
         s.value > uint32(H2MaxFrameSizeMax):
        h2.connError(H2ProtocolError)
        return
      h2.peerMaxFrame = int(s.value)
    of 6:  # MAX_HEADER_LIST_SIZE: advisory, stored.
      discard
    else:
      discard  # Unknown settings are ignored (§6.5).

proc handleSettings(h2: H2Conn, f: H2Frame) =
  if (f.flags and H2FlagAck) != 0:
    h2.peerAckedSettings = true
    return
  var settings: seq[H2Setting]
  try:
    settings = f.decodeSettings()
  except H2Error as e:
    h2.connError(e.code)
    return
  h2.applyPeerSettings(settings)
  if h2.state == CsClosed:
    return
  discard h2.conn.send(encodeSettingsAck())
  if h2.onSettingsApplied != nil:
    h2.onSettingsApplied(h2)

# ── Response path ─────────────────────────────────────────────────────

proc flushPending(h2: H2Conn) =
  ## Drain queued DATA while connection and stream windows allow.
  ## Order is preserved: the head blocks the queue.
  while h2.pending.len > 0:
    if h2.state == CsClosed:
      return
    var head = h2.pending[0]
    if not h2.streams.hasKey(head.sid):
      h2.pending.delete(0)
      continue
    let stream = h2.streams[head.sid]
    let avail = min([h2.sendWindow, stream.sendWindow,
                     int32(h2.peerMaxFrame)])
    if avail <= 0:
      return
    let n = min(avail, int32(head.data.len - head.offset))
    let last = head.offset + int(n) == head.data.len and head.endStream
    var flags: uint8 = 0
    if last:
      flags = flags or H2FlagEndStream
    discard h2.conn.send(encodeFrame(0, flags, head.sid,
      head.data.toOpenArray(head.offset, head.offset + int(n) - 1)))
    h2.sendWindow -= n
    stream.sendWindow -= n
    head.offset += int(n)
    if head.offset >= head.data.len:
      h2.pending.delete(0)
      if last and h2.streams.hasKey(head.sid):
        # Mirror sendDataChunked: only a half-closed (remote) stream is
        # done; otherwise we are half-closed (local) and still expect
        # the peer's END_STREAM (client request path).
        if h2.streams[head.sid].state == HsHalfClosedRemote:
          h2.closeStream(head.sid)
        else:
          h2.streams[head.sid].state = HsHalfClosedLocal
    else:
      h2.pending[0] = head
      return

proc sendDataChunked(h2: H2Conn, sid: int32, body: seq[byte],
                     endStream: bool) =
  var offset = 0
  while offset < body.len:
    if not h2.streams.hasKey(sid) or h2.state == CsClosed:
      return
    let stream = h2.streams[sid]
    let avail = min([h2.sendWindow, stream.sendWindow,
                     int32(h2.peerMaxFrame)])
    if avail <= 0:
      h2.pending.add(H2PendingWrite(sid: sid, data: body, offset: offset,
                                    endStream: endStream))
      return
    let n = min(avail, int32(body.len - offset))
    let last = offset + int(n) == body.len and endStream
    var flags: uint8 = 0
    if last:
      flags = flags or H2FlagEndStream
    discard h2.conn.send(encodeFrame(0, flags, sid,
      body.toOpenArray(offset, offset + int(n) - 1)))
    h2.sendWindow -= n
    stream.sendWindow -= n
    offset += int(n)
  if offset >= body.len and endStream and h2.streams.hasKey(sid):
    if h2.streams[sid].state == HsHalfClosedRemote:
      h2.closeStream(sid)
    else:
      h2.streams[sid].state = HsHalfClosedLocal

proc respond431(h2: H2Conn, sid: int32) =
  ## Oversize header block → HTTP 431 + close the stream (§10.5).
  if not h2.streams.hasKey(sid):
    return
  let blk =
    try:
      h2.encCtx.encode(@[HpackHeader(name: ":status", value: "431")])
    except HpackError:
      h2.streamError(sid, H2InternalError)
      return
  discard h2.conn.send(encodeHeaders(sid, blk, endStream = false))
  var body = newSeq[byte]("Request Header Fields Too Large".len)
  const msg = "Request Header Fields Too Large"
  for i, c in msg:
    body[i] = byte(c)
  h2.sendDataChunked(sid, body, endStream = true)
  # Done with this stream regardless of which half closed first.
  if h2.streams.hasKey(sid):
    h2.closeStream(sid)

proc status*(res: H2Response, code: uint16): H2Response {.discardable.} =
  res.status = code
  res

proc header*(res: H2Response, name, value: string): H2Response {.discardable.} =
  res.headers.add((name.toLowerAscii(), value))
  res

proc send*(res: H2Response, body: seq[byte]) =
  let h2 = res.h2
  if res.sent or not h2.streams.hasKey(res.streamId):
    return
  res.sent = true
  var hs = @[HpackHeader(name: ":status", value: $res.status)]
  hs.add(HpackHeader(name: "content-length", value: $body.len))
  for (n, v) in res.headers:
    if n == ":status" or n == "content-length":
      continue
    hs.add(HpackHeader(name: n, value: v))
  let blk =
    try:
      h2.encCtx.encode(hs)
    except HpackError:
      h2.streamError(res.streamId, H2InternalError)
      return
  if h2.state == CsClosed or not h2.streams.hasKey(res.streamId):
    return
  discard h2.conn.send(encodeHeaders(res.streamId, blk,
    endStream = body.len == 0))
  if body.len > 0:
    h2.sendDataChunked(res.streamId, body, endStream = true)
  elif h2.streams.hasKey(res.streamId):
    if h2.streams[res.streamId].state == HsHalfClosedRemote:
      h2.closeStream(res.streamId)
    else:
      h2.streams[res.streamId].state = HsHalfClosedLocal

proc send*(res: H2Response, body: string) =
  var b = newSeq[byte](body.len)
  for i, c in body:
    b[i] = byte(c)
  res.send(b)

proc reset*(res: H2Response, code = H2Cancelled) =
  ## Abort the stream with RST_STREAM (e.g. handler rejects the request).
  let h2 = res.h2
  if res.sent or not h2.streams.hasKey(res.streamId):
    return
  res.sent = true
  h2.streamError(res.streamId, code)

# ── Request validation + dispatch ─────────────────────────────────────

proc splitRequestHeaders(hs: seq[HpackHeader]): tuple[ok: bool, req: H2Request] =
  ## Validate pseudo-headers (§8.1.2) and split regular headers. Uppercase
  ## names, connection-specific headers, and missing pseudo-headers fail
  ## with ok == false (caller sends RST_STREAM(PROTOCOL_ERROR)).
  var req = H2Request(headers: @[], body: @[])
  var seenMethod, seenScheme, seenPath: bool
  for h in hs:
    if h.name.len == 0:
      return (false, req)
    if h.name[0] == ':':
      if req.headers.len > 0:
        return (false, req)  # pseudo-header after regular headers
      case h.name
      of ":method":
        if seenMethod: return (false, req)
        seenMethod = true
        req.meth = h.value
      of ":scheme":
        if seenScheme: return (false, req)
        seenScheme = true
        req.scheme = h.value
      of ":path":
        if seenPath: return (false, req)
        seenPath = true
        req.path = h.value
      of ":authority":
        req.authority = h.value
      else:
        return (false, req)
    else:
      for c in h.name:
        if c >= 'A' and c <= 'Z':
          return (false, req)
      case h.name
      of "connection", "keep-alive", "transfer-encoding", "upgrade":
        return (false, req)
      of "te":
        if h.value != "trailers":
          return (false, req)
        req.headers.add((h.name, h.value))
      else:
        req.headers.add((h.name, h.value))
  if not (seenMethod and seenScheme and seenPath):
    return (false, req)
  if req.meth.len == 0 or req.path.len == 0:
    return (false, req)
  (true, req)

proc dispatchStream(h2: H2Conn, stream: H2Stream) =
  let (ok, mutReq) = splitRequestHeaders(stream.reqHeaders)
  if not ok:
    h2.streamError(stream.id, H2ProtocolError)
    return
  var req = mutReq
  req.streamId = stream.id
  req.body = stream.reqBody
  var contentLength = -1'i64
  for (n, v) in req.headers:
    if n == "content-length":
      try:
        contentLength = parseBiggestInt(v)
      except ValueError:
        h2.streamError(stream.id, H2ProtocolError)
        return
      break
  if contentLength >= 0 and int64(stream.reqBody.len) != contentLength:
    h2.streamError(stream.id, H2ProtocolError)
    return
  let res = H2Response(h2: h2, streamId: stream.id, status: 200,
                       headers: @[], sent: false)
  try:
    h2.onRequest(req, res)
  except CatchableError:
    if not res.sent and h2.streams.hasKey(stream.id):
      res.status = 500
      res.send("Internal Server Error")
    elif h2.streams.hasKey(stream.id):
      h2.streamError(stream.id, H2InternalError)
  if not res.sent and h2.streams.hasKey(stream.id):
    # Handler returned without responding: fail safe with 500.
    res.status = 500
    res.send("Internal Server Error")

# ── HEADERS / CONTINUATION / DATA ─────────────────────────────────────

proc headerListSize(hs: seq[HpackHeader]): int =
  for h in hs:
    result += h.name.len + h.value.len

proc decodeFragBlock(h2: H2Conn, sid: int32): bool =
  ## HPACK-decode `fragBuf` into the stream's header list. Returns false
  ## after raising a stream error.
  let stream = h2.streams.getOrDefault(sid)
  if stream == nil:
    return false
  var decoded: seq[HpackHeader]
  try:
    decoded = h2.decCtx.decode(h2.fragBuf)
  except HpackError:
    h2.streamError(sid, H2CompressionError)
    return false
  for h in decoded:
    stream.reqHeaders.add(h)
  true

proc handleHeaders(h2: H2Conn, f: H2Frame) =
  if h2.fragStream >= 0:
    h2.connError(H2ProtocolError)  # HEADERS mid-CONTINUATION
    return
  let sid = f.streamId
  var fragment = f.payload
  if (f.flags and H2FlagPriority) != 0:
    # PRIORITY data rides the first 5 octets; validated, then ignored.
    if fragment.len < 5:
      h2.connError(H2ProtocolError)
      return
    if fragment.len == 5:
      fragment = @[]
    else:
      fragment = fragment[5 .. ^1]
  if h2.streams.hasKey(sid):
    # Trailer block on a half-closed (remote) stream.
    let stream = h2.streams[sid]
    if stream.state != HsHalfClosedRemote or
       (f.flags and H2FlagEndStream) == 0:
      h2.connError(H2ProtocolError)
      return
    if (f.flags and H2FlagEndHeaders) != 0:
      h2.fragBuf = fragment
      if not h2.decodeFragBlock(sid):
        return
      if headerListSize(stream.reqHeaders) > h2.maxHeaderList:
        h2.respond431(sid)
        return
      stream.state = HsClosed
      h2.dispatchStream(stream)
    else:
      h2.fragStream = sid
      h2.fragBuf = fragment
      h2.fragEndStream = true
    return
  # New stream: client-initiated ids are odd and increasing.
  if sid == 0 or (sid and 1) == 0 or sid <= h2.lastPeerSid:
    h2.connError(H2ProtocolError)
    return
  if h2.goawayReceived:
    h2.streamError(sid, H2RefusedStream)
    return
  if h2.openCount >= h2.maxConcurrentLocal:
    h2.streamError(sid, H2RefusedStream)
    return
  h2.lastPeerSid = sid
  let stream = H2Stream(id: sid, state: HsOpen, reqHeaders: @[],
                        reqBody: @[],
                        recvWindow: H2DefaultWindowSize,
                        sendWindow: h2.peerInitWindow)
  h2.streams[sid] = stream
  inc h2.openCount
  if (f.flags and H2FlagEndHeaders) != 0:
    h2.fragBuf = fragment
    if not h2.decodeFragBlock(sid):
      return
    if headerListSize(stream.reqHeaders) > h2.maxHeaderList:
      h2.respond431(sid)
      return
    if (f.flags and H2FlagEndStream) != 0:
      stream.state = HsHalfClosedRemote
      h2.dispatchStream(stream)
  else:
    h2.fragStream = sid
    h2.fragBuf = fragment
    h2.fragEndStream = (f.flags and H2FlagEndStream) != 0

proc handleContinuation(h2: H2Conn, f: H2Frame) =
  if h2.fragStream < 0 or f.streamId != h2.fragStream:
    h2.connError(H2ProtocolError)
    return
  let sid = f.streamId
  let wasTrailer = h2.streams.hasKey(sid) and
    h2.streams[sid].reqHeaders.len > 0
  for b in f.payload:
    h2.fragBuf.add(b)
  if (f.flags and H2FlagEndHeaders) == 0:
    return
  let endStream = h2.fragEndStream
  h2.fragStream = -1
  h2.fragEndStream = false
  if not h2.streams.hasKey(sid):
    h2.connError(H2ProtocolError)
    return
  let stream = h2.streams[sid]
  if not h2.decodeFragBlock(sid):
    return
  if headerListSize(stream.reqHeaders) > h2.maxHeaderList:
    h2.respond431(sid)
    return
  # CONTINUATION never carries END_STREAM; the flag arrived on the HEADERS
  # that opened the block. A trailer block always ends the stream.
  if wasTrailer:
    stream.state = HsClosed
    h2.dispatchStream(stream)
  elif endStream:
    stream.state = HsHalfClosedRemote
    h2.dispatchStream(stream)

proc handleData(h2: H2Conn, f: H2Frame) =
  if h2.fragStream >= 0:
    h2.connError(H2ProtocolError)  # DATA mid-CONTINUATION
    return
  let sid = f.streamId
  if not h2.streams.hasKey(sid):
    if sid <= h2.lastPeerSid:
      # Data for a closed stream.
      if h2.state != CsClosed:
        discard h2.conn.send(encodeRstStream(sid, H2StreamClosed))
    else:
      h2.connError(H2ProtocolError)  # DATA on idle stream
    return
  let stream = h2.streams[sid]
  if stream.state != HsOpen:
    h2.streamError(sid, H2StreamClosed)
    return
  if int64(f.payload.len) > int64(stream.recvWindow) or
     int64(f.payload.len) > int64(h2.recvWindow):
    h2.connError(H2FlowControlError)
    return
  stream.recvWindow -= int32(f.payload.len)
  h2.recvWindow -= int32(f.payload.len)
  if stream.reqBody.len + f.payload.len > h2.maxBody:
    h2.streamError(sid, H2Cancelled)
    return
  for b in f.payload:
    stream.reqBody.add(b)
  h2.topUpRecv(sid, stream)
  if (f.flags and H2FlagEndStream) != 0:
    stream.state = HsHalfClosedRemote
    if h2.fragStream < 0:
      h2.dispatchStream(stream)

# ── Client role (M4) ────────────────────────────────────────────────
#
# Client streams live in the same `streams` table (odd ids opened locally).
# Responses accumulate on the stream's `respHeaders`/`respBody`; completion
# or failure delivers exactly one `clientCb` invocation, then the stream is
# dropped. The shared send path (`sendDataChunked`, `flushPending`) and
# receive top-ups are reused verbatim.

proc sendHeaderBlock(h2: H2Conn, sid: int32, blk: seq[byte],
                     endStream: bool) =
  ## Emit HEADERS, fragmenting across CONTINUATION past `peerMaxFrame`.
  if blk.len <= h2.peerMaxFrame:
    var flags = H2FlagEndHeaders
    if endStream:
      flags = flags or H2FlagEndStream
    discard h2.conn.send(encodeFrame(1, flags, sid, blk))
    return
  var off = 0
  var first = true
  while off < blk.len:
    let n = min(h2.peerMaxFrame, blk.len - off)
    let last = off + n == blk.len
    var fl: uint8 = 0
    if first and endStream:
      fl = fl or H2FlagEndStream
    if last:
      fl = fl or H2FlagEndHeaders
    discard h2.conn.send(encodeFrame(if first: 1 else: 9, fl, sid,
      blk.toOpenArray(off, off + n - 1)))
    off += n
    first = false

proc startClientPreface*(h2: H2Conn) =
  ## Switch a fresh `H2Conn` to the client role and emit the preface:
  ## magic + SETTINGS with push disabled. The peer's frames drive the rest.
  h2.state = CsReady
  h2.prefaceSettingsSeen = true
  discard h2.conn.send(H2ConnMagic)
  discard h2.conn.send(encodeSettings([H2Setting(id: 2, value: 0)]))

proc openClientStream*(h2: H2Conn, headers: seq[HpackHeader],
                       body: seq[byte], endStream: bool,
                       cb: H2ClientCallback): int32 =
  ## Open a client-initiated stream and send the request. Returns the
  ## stream id, or -1 when refused (closed, GOAWAY received, no capacity,
  ## id exhaustion, HPACK failure) — the callback is NOT invoked on -1.
  if h2.state == CsClosed or h2.goawayReceived:
    return -1
  if h2.openCount >= min(h2.peerMaxConcurrent, h2.maxConcurrentLocal):
    return -1
  if h2.nextStreamId > 2147483647'i32 - 2:
    return -1
  var blk: seq[byte]
  try:
    blk = h2.encCtx.encode(headers)
  except HpackError:
    return -1
  let sid = h2.nextStreamId
  h2.nextStreamId += 2
  let stream = H2Stream(id: sid, state: HsOpen, reqHeaders: @[],
                        reqBody: @[], respHeaders: @[], respBody: @[],
                        clientCb: cb,
                        recvWindow: H2DefaultWindowSize,
                        sendWindow: h2.peerInitWindow)
  h2.streams[sid] = stream
  inc h2.openCount
  h2.sendHeaderBlock(sid, blk, endStream and body.len == 0)
  if body.len > 0:
    h2.sendDataChunked(sid, body, endStream)
  elif endStream:
    stream.state = HsHalfClosedLocal
  sid

proc failClientStream(h2: H2Conn, sid: int32, err: string,
                      code = H2Cancelled) =
  ## RST the stream and deliver exactly one error to its callback.
  if not h2.streams.hasKey(sid):
    return
  let stream = h2.streams[sid]
  let cb = stream.clientCb
  stream.clientCb = nil
  if h2.state != CsClosed:
    discard h2.conn.send(encodeRstStream(sid, code))
  h2.closeStream(sid)
  if cb != nil:
    cb(H2ClientResponse(), err)

proc finishClientStream(h2: H2Conn, sid: int32) =
  ## Assemble the response and deliver it, then drop the stream.
  if not h2.streams.hasKey(sid):
    return
  let stream = h2.streams[sid]
  let cb = stream.clientCb
  stream.clientCb = nil
  let body = stream.respBody
  var status = -1
  var headers: seq[(string, string)] = @[]
  for h in stream.respHeaders:
    if h.name.len > 0 and h.name[0] == ':':
      if h.name == ":status":
        try:
          status = parseInt(h.value)
        except ValueError:
          status = -1
    else:
      headers.add((h.name, h.value))
  h2.closeStream(sid)
  if cb != nil:
    if status < 0:
      cb(H2ClientResponse(), "protocol error")
    else:
      cb(H2ClientResponse(status: status, headers: headers, body: body),
         "")

proc decodeFragBlockResp(h2: H2Conn, sid: int32): bool =
  let stream = h2.streams.getOrDefault(sid)
  if stream == nil or stream.clientCb == nil:
    return false
  var decoded: seq[HpackHeader]
  try:
    decoded = h2.decCtx.decode(h2.fragBuf)
  except HpackError:
    h2.failClientStream(sid, "protocol error", H2CompressionError)
    return false
  for h in decoded:
    stream.respHeaders.add(h)
  true

proc handleClientHeaders(h2: H2Conn, f: H2Frame) =
  let sid = f.streamId
  if sid <= 0 or (sid and 1) == 0:
    h2.connError(H2ProtocolError)  # servers never open streams (no push)
    return
  if not h2.streams.hasKey(sid):
    if sid < h2.nextStreamId:
      if h2.state != CsClosed:
        discard h2.conn.send(encodeRstStream(sid, H2StreamClosed))
    else:
      h2.connError(H2ProtocolError)  # response for an idle stream
    return
  let stream = h2.streams[sid]
  if stream.clientCb == nil:
    h2.connError(H2ProtocolError)
    return
  if h2.fragStream >= 0 and h2.fragStream != sid:
    h2.connError(H2ProtocolError)
    return
  var fragment = f.payload
  if (f.flags and H2FlagPriority) != 0:
    if fragment.len < 5:
      h2.connError(H2ProtocolError)
      return
    fragment = if fragment.len == 5: @[] else: fragment[5 .. ^1]
  let firstBlock = stream.respHeaders.len == 0
  h2.fragBuf = fragment
  if (f.flags and H2FlagEndHeaders) == 0:
    h2.fragStream = sid
    h2.fragEndStream = (f.flags and H2FlagEndStream) != 0
    return
  h2.fragEndStream = false
  if not h2.decodeFragBlockResp(sid):
    return
  if firstBlock and not stream.respHeaders.anyIt(it.name == ":status"):
    h2.failClientStream(sid, "protocol error", H2ProtocolError)
    return
  if (f.flags and H2FlagEndStream) != 0:
    h2.finishClientStream(sid)

proc handleClientContinuation(h2: H2Conn, f: H2Frame) =
  if h2.fragStream < 0 or f.streamId != h2.fragStream:
    h2.connError(H2ProtocolError)
    return
  let sid = f.streamId
  if not h2.streams.hasKey(sid) or h2.streams[sid].clientCb == nil:
    h2.connError(H2ProtocolError)
    return
  let stream = h2.streams[sid]
  let firstBlock = stream.respHeaders.len == 0
  for b in f.payload:
    h2.fragBuf.add(b)
  if (f.flags and H2FlagEndHeaders) == 0:
    return
  h2.fragStream = -1
  if not h2.decodeFragBlockResp(sid):
    return
  if firstBlock and not stream.respHeaders.anyIt(it.name == ":status"):
    h2.failClientStream(sid, "protocol error", H2ProtocolError)
    return
  if h2.fragEndStream:
    h2.fragEndStream = false
    h2.finishClientStream(sid)

proc handleClientData(h2: H2Conn, f: H2Frame) =
  if h2.fragStream >= 0:
    h2.connError(H2ProtocolError)
    return
  let sid = f.streamId
  if not h2.streams.hasKey(sid):
    if sid <= 0 or (sid and 1) == 0:
      h2.connError(H2ProtocolError)
    elif sid < h2.nextStreamId:
      if h2.state != CsClosed:
        discard h2.conn.send(encodeRstStream(sid, H2StreamClosed))
    else:
      h2.connError(H2ProtocolError)  # DATA on idle stream
    return
  let stream = h2.streams[sid]
  if stream.clientCb == nil:
    h2.connError(H2ProtocolError)
    return
  if stream.respHeaders.len == 0:
    # DATA before any response HEADERS.
    h2.failClientStream(sid, "protocol error", H2ProtocolError)
    return
  if int64(f.payload.len) > int64(stream.recvWindow) or
     int64(f.payload.len) > int64(h2.recvWindow):
    h2.connError(H2FlowControlError)
    return
  stream.recvWindow -= int32(f.payload.len)
  h2.recvWindow -= int32(f.payload.len)
  if stream.respBody.len + f.payload.len > h2.maxBody:
    h2.failClientStream(sid, "response too large")
    return
  for b in f.payload:
    stream.respBody.add(b)
  h2.topUpRecv(sid, stream)
  if (f.flags and H2FlagEndStream) != 0:
    h2.finishClientStream(sid)

proc handleClientRst(h2: H2Conn, f: H2Frame) =
  let sid = f.streamId
  if not h2.streams.hasKey(sid):
    if sid <= 0 or (sid and 1) == 0 or sid >= h2.nextStreamId:
      h2.connError(H2ProtocolError)
    return
  let stream = h2.streams[sid]
  if stream.clientCb == nil:
    h2.connError(H2ProtocolError)
    return
  let cb = stream.clientCb
  stream.clientCb = nil
  h2.closeStream(sid)
  if cb != nil:
    cb(H2ClientResponse(), "reset by peer")

# ── PING / WINDOW_UPDATE / RST / GOAWAY ───────────────────────────────

proc handlePing(h2: H2Conn, f: H2Frame) =
  if (f.flags and H2FlagAck) != 0:
    return  # client-role hook lands in M4
  var opaque: array[8, byte]
  try:
    opaque = f.decodePing()
  except H2Error as e:
    h2.connError(e.code)
    return
  discard h2.conn.send(encodePingAck(opaque))

proc handleWindowUpdate(h2: H2Conn, f: H2Frame) =
  var inc: uint32
  try:
    inc = f.decodeWindowUpdate()
  except H2Error as e:
    h2.connError(e.code)
    return
  if f.streamId == 0:
    if int64(h2.sendWindow) + int64(inc) > int64(H2MaxWindowSize):
      h2.connError(H2FlowControlError)
      return
    h2.sendWindow += int32(inc)
  else:
    let sid = f.streamId
    if not h2.streams.hasKey(sid):
      if sid > h2.lastPeerSid:
        h2.connError(H2ProtocolError)
      return
    let stream = h2.streams[sid]
    if int64(stream.sendWindow) + int64(inc) > int64(H2MaxWindowSize):
      h2.connError(H2FlowControlError)
      return
    stream.sendWindow += int32(inc)
  h2.flushPending()

proc handleRst(h2: H2Conn, f: H2Frame) =
  let sid = f.streamId
  if not h2.streams.hasKey(sid):
    if sid > h2.lastPeerSid:
      h2.connError(H2ProtocolError)
    return
  h2.closeStream(sid)

proc handleGoaway(h2: H2Conn, f: H2Frame) =
  try:
    discard f.decodeGoaway()
  except H2Error as e:
    h2.connError(e.code)
    return
  h2.goawayReceived = true
  if h2.openCount <= 0:
    h2.state = CsClosed
    h2.conn.close()

proc handleFrame(h2: H2Conn, f: H2Frame) =
  let clientRole = h2.role == H2ClientRole
  case f.rawType
  of 0:
    if clientRole: h2.handleClientData(f)
    else: h2.handleData(f)
  of 1:
    if clientRole: h2.handleClientHeaders(f)
    else: h2.handleHeaders(f)
  of 2: discard  # PRIORITY validated by the codec; no scheduling (deferred).
  of 3:
    if clientRole: h2.handleClientRst(f)
    else: h2.handleRst(f)
  of 4: h2.handleSettings(f)
  of 5: h2.connError(H2ProtocolError)  # PUSH_PROMISE deferred.
  of 6: h2.handlePing(f)
  of 7: h2.handleGoaway(f)
  of 8: h2.handleWindowUpdate(f)
  of 9:
    if clientRole: h2.handleClientContinuation(f)
    else: h2.handleContinuation(f)
  else: discard  # Unknown frames are ignored (§5.5).

# ── Preface: prior knowledge + Upgrade ────────────────────────────────

proc sendServerPreface(h2: H2Conn) =
  discard h2.conn.send(encodeSettings(newSeq[H2Setting]()))

proc b64urlDecode(s: string): seq[byte] =
  ## HTTP2-Settings is base64url without padding (§3.2).
  var std = s
  std = std.replace('-', '+').replace('_', '/')
  while std.len mod 4 != 0:
    std.add('=')
  let raw =
    try:
      decode(std)
    except CatchableError:
      raise hpackError("h2: bad HTTP2-Settings encoding")
  result = newSeq[byte](raw.len)
  for i, c in raw:
    result[i] = byte(c)

proc parseH1Headers(buf: seq[byte]): tuple[ok: bool, meth, target: string,
    headers: Table[string, string]] =
  var headers = initTable[string, string]()
  var text = newString(buf.len)
  for i, b in buf: text[i] = char(b)
  let headEnd = text.find("\r\n\r\n")
  if headEnd < 0:
    return (false, "", "", headers)
  let head = text[0 ..< headEnd].split("\r\n")
  if head.len == 0:
    return (false, "", "", headers)
  let parts = head[0].split(' ')
  if parts.len != 3 or not parts[2].startsWith("HTTP/1."):
    return (false, "", "", headers)
  for i in 1 ..< head.len:
    let c = head[i].find(':')
    if c < 0:
      continue
    headers[head[i][0 ..< c].strip().toLowerAscii()] =
      head[i][c+1 .. ^1].strip()
  (true, parts[0], parts[1], headers)

proc looksLikeH1(buf: seq[byte]): bool =
  if buf.len == 0:
    return false
  for m in H2UpgradeMethods:
    if buf.len >= m.len:
      var match = true
      for i in 0 ..< m.len:
        if char(buf[i]) != m[i]:
          match = false
          break
      if match:
        return true
  false

proc isMagicPrefix(buf: seq[byte]): bool =
  for i in 0 ..< min(buf.len, H2ConnMagic.len):
    if char(buf[i]) != H2ConnMagic[i]:
      return false
  true

proc handleUpgrade(h2: H2Conn): bool =
  ## Attempt an H1 → h2c upgrade from `sniffBuf`. Returns true when the
  ## connection reached a terminal decision (upgraded or rejected).
  let (ok, meth, target, headers) = parseH1Headers(h2.sniffBuf)
  if not ok:
    if h2.sniffBuf.len >= H2SniffCap:
      h2.conn.close()
      h2.state = CsClosed
      return true
    return false
  proc reject(statusLine: string) =
    discard h2.conn.send(statusLine & "Content-Length: 0\r\n" &
      "Connection: close\r\n\r\n")
    h2.conn.close()
    h2.state = CsClosed
  let upgrade = headers.getOrDefault("upgrade", "").toLowerAscii()
  let settingsB64 = headers.getOrDefault("http2-settings", "")
  if not upgrade.split(',').anyIt(it.strip() == "h2c") or
     settingsB64.len == 0:
    # Not for us: 426 then close (h2c-only port in M2).
    reject("HTTP/1.1 426 Upgrade Required\r\nUpgrade: h2c\r\n")
    return true
  if headers.getOrDefault("content-length", "0") != "0":
    reject("HTTP/1.1 400 Bad Request\r\n")
    return true
  var settingsRaw: seq[byte]
  try:
    settingsRaw = b64urlDecode(settingsB64)
  except HpackError:
    h2.conn.close()
    h2.state = CsClosed
    return true
  if settingsRaw.len mod 6 != 0:
    h2.conn.close()
    h2.state = CsClosed
    return true
  # The H1 request becomes stream 1, half-closed (remote).
  let stream = H2Stream(id: 1, state: HsHalfClosedRemote, reqHeaders: @[],
                        reqBody: @[],
                        recvWindow: H2DefaultWindowSize,
                        sendWindow: h2.peerInitWindow)
  stream.reqHeaders.add(HpackHeader(name: ":method", value: meth))
  stream.reqHeaders.add(HpackHeader(name: ":path", value: target))
  stream.reqHeaders.add(HpackHeader(name: ":scheme", value: "http"))
  stream.reqHeaders.add(HpackHeader(name: ":authority",
    value: headers.getOrDefault("host", "")))
  for k, v in headers:
    if k in ["connection", "upgrade", "http2-settings", "host",
             "content-length"]:
      continue
    stream.reqHeaders.add(HpackHeader(name: k, value: v))
  # Embedded SETTINGS stand in for the client's SETTINGS frame: applied,
  # never ACKed (no SETTINGS frame was received).
  var embedded: seq[H2Setting]
  var pos = 0
  while pos < settingsRaw.len:
    embedded.add(H2Setting(
      id: uint16((uint16(settingsRaw[pos]) shl 8) or
                 uint16(settingsRaw[pos+1])),
      value: (uint32(settingsRaw[pos+2]) shl 24) or
             (uint32(settingsRaw[pos+3]) shl 16) or
             (uint32(settingsRaw[pos+4]) shl 8) or
             uint32(settingsRaw[pos+5])))
    pos += 6
  discard h2.conn.send("HTTP/1.1 101 Switching Protocols\r\n" &
    "Connection: Upgrade\r\nUpgrade: h2c\r\n\r\n")
  h2.sendServerPreface()
  h2.applyPeerSettings(embedded)
  if h2.state == CsClosed:
    return true
  h2.streams[1] = stream
  h2.lastPeerSid = 1
  inc h2.openCount
  h2.sniffBuf.setLen(0)
  h2.state = CsPreface  # upgraded conns still open with the client magic
  h2.prefaceSettingsSeen = true  # embedded settings replace the frame
  h2.dispatchStream(stream)
  true

proc feedReady(h2: H2Conn, data: openArray[byte]) =
  let frames =
    try:
      h2.parser.feed(data)
    except H2Error as e:
      h2.connError(e.code)
      return
  for f in frames:
    h2.handleFrame(f)
    if h2.state == CsClosed or h2.state == CsDraining:
      return

proc feedPreface(h2: H2Conn, data: openArray[byte])
proc feedSniff(h2: H2Conn, data: openArray[byte]) =
  for b in data:
    h2.sniffBuf.add(b)
  if h2.sniffBuf.len > H2SniffCap:
    h2.conn.close()
    h2.state = CsClosed
    return
  if isMagicPrefix(h2.sniffBuf):
    if h2.sniffBuf.len < H2ConnMagic.len:
      return  # wait for the full magic
    var rest = newSeq[byte](h2.sniffBuf.len - H2ConnMagic.len)
    for i in 0 ..< rest.len:
      rest[i] = h2.sniffBuf[H2ConnMagic.len + i]
    h2.sniffBuf.setLen(0)
    h2.state = CsPreface
    h2.sendServerPreface()
    if rest.len > 0:
      # Route through the preface gate (not feedReady): the client's
      # SETTINGS may be in this batch and must flip prefaceSettingsSeen.
      h2.feedPreface(rest)
    return
  # Not the magic: either an H1 upgrade or garbage.
  if looksLikeH1(h2.sniffBuf):
    var text = newString(h2.sniffBuf.len)
    for i, b in h2.sniffBuf: text[i] = char(b)
    if text.find("\r\n\r\n") >= 0:
      discard h2.handleUpgrade()
    return
  if h2.sniffBuf.len >= 8:
    # Neither magic prefix nor H1 method: not our protocol.
    h2.conn.close()
    h2.state = CsClosed

proc feedPreface(h2: H2Conn, data: openArray[byte]) =
  ## Upgraded conns open with the 24-byte client magic; prior-knowledge
  ## conns open with a SETTINGS frame.
  if h2.prefaceSettingsSeen:
    for b in data:
      h2.sniffBuf.add(b)
    if h2.sniffBuf.len < H2ConnMagic.len:
      return
    if h2.sniffBuf.len > H2SniffCap:
      h2.conn.close()
      h2.state = CsClosed
      return
    for i in 0 ..< H2ConnMagic.len:
      if char(h2.sniffBuf[i]) != H2ConnMagic[i]:
        h2.connError(H2ProtocolError)
        return
    var rest = newSeq[byte](h2.sniffBuf.len - H2ConnMagic.len)
    for i in 0 ..< rest.len:
      rest[i] = h2.sniffBuf[H2ConnMagic.len + i]
    h2.sniffBuf.setLen(0)
    h2.state = CsReady
    if rest.len > 0:
      h2.feedReady(rest)
    return
  # Prior knowledge: frames directly; the first MUST be SETTINGS.
  let frames =
    try:
      h2.parser.feed(data)
    except H2Error as e:
      h2.connError(e.code)
      return
  for f in frames:
    if not h2.prefaceSettingsSeen:
      if f.rawType != 4:
        h2.connError(H2ProtocolError)
        return
      h2.prefaceSettingsSeen = true
      h2.state = CsReady
    h2.handleFrame(f)
    if h2.state == CsClosed or h2.state == CsDraining:
      return

proc feedH2*(h2: H2Conn, data: openArray[byte]) =
  ## Entry point for inbound TCP bytes.
  case h2.state
  of CsSniff: h2.feedSniff(data)
  of CsPreface: h2.feedPreface(data)
  of CsReady: h2.feedReady(data)
  of CsDraining, CsClosed: discard

proc h2Closed*(h2: H2Conn): bool {.inline.} =
  ## True once the connection reached its terminal state.
  h2 == nil or h2.state == CsClosed

proc h2Draining*(h2: H2Conn): bool {.inline.} =
  ## True once the peer asked to go away (no new streams accepted).
  h2 != nil and h2.goawayReceived

proc newH2Conn*(conn: Connection, role: H2Role,
                onRequest: OnH2RequestCallback,
                maxConcurrent = H2DefaultMaxConcurrent,
                maxHeaderList = H2DefaultMaxHeaderList,
                maxBody = H2DefaultMaxBody): H2Conn =
  H2Conn(conn: conn, role: role, state: CsSniff,
         parser: newH2FrameParser(),
         encCtx: newHpackContext(), decCtx: newHpackContext(),
         streams: initTable[int32, H2Stream](16),
         sniffBuf: @[], fragStream: -1, fragBuf: @[],
         fragEndStream: false,
         prefaceSettingsSeen: false, lastPeerSid: 0, openCount: 0,
         recvWindow: H2DefaultWindowSize, sendWindow: H2DefaultWindowSize,
         peerInitWindow: H2DefaultWindowSize,
         peerMaxFrame: H2DefaultMaxFrameSize,
         peerMaxConcurrent: high(int), nextStreamId: 1,
         maxConcurrentLocal: maxConcurrent, maxHeaderList: maxHeaderList,
         maxBody: maxBody, peerAckedSettings: false,
         goawayReceived: false, goawaySent: false, pending: @[],
         onRequest: onRequest, onSettingsApplied: nil, alpnChecked: false)

# ── H2Server ──────────────────────────────────────────────────────────

proc newH2Server*(loop: Loop, handler: OnH2RequestCallback,
                  maxConcurrent = H2DefaultMaxConcurrent,
                  maxHeaderList = H2DefaultMaxHeaderList,
                  maxBody = H2DefaultMaxBody,
                  sslCtx: SslContext = nil): H2Server =
  ## Create an h2c server, or an `h2` (TLS) server when `sslCtx` is given.
  ## A TLS server advertises ALPN `["h2"]` only: peers negotiating anything
  ## else are closed after the handshake (H1 fallback on the same port is
  ## future work).
  let s = H2Server(loop: loop, handler: handler, sslCtx: sslCtx,
                   conns: initTable[int, H2Conn](64),
                   maxConcurrent: maxConcurrent,
                   maxHeaderList: maxHeaderList, maxBody: maxBody)
  when not defined(windows):
    if sslCtx != nil:
      sslCtx.setAlpnProtocols(["h2"])
  let tcp = newTcpServer(loop,
    onAccept = proc(conn: Connection) =
      when not defined(windows):
        if s.sslCtx != nil:
          conn.wrapTls(s.sslCtx)
      let h2 = newH2Conn(conn, H2ServerRole, s.handler, s.maxConcurrent,
                         s.maxHeaderList, s.maxBody)
      s.conns[conn.fd.int] = h2
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      let h2 = s.conns.getOrDefault(conn.fd.int)
      if h2 == nil:
        conn.close()
        return
      when not defined(windows):
        if s.sslCtx != nil:
          # The TCP layer only delivers post-handshake plaintext here.
          if not conn.isTlsActive():
            return
          if not h2.alpnChecked:
            h2.alpnChecked = true
            if conn.alpnSelected() != "h2":
              s.conns.del(conn.fd.int)
              conn.close()
              return
      h2.feedH2(data)
      if h2.state == CsClosed and h2.openCount <= 0 and
         h2.pending.len == 0:
        s.conns.del(conn.fd.int)
    ,
    onClose = proc(conn: Connection) =
      s.conns.del(conn.fd.int)
  )
  s.tcp = tcp
  s

proc listen*(s: H2Server, address: string, port: int) =
  s.tcp.listen(address, port)

proc close*(s: H2Server) =
  for _, h2 in s.conns:
    if not h2.goawaySent and h2.state != CsClosed:
      h2.goawaySent = true
      discard h2.conn.send(encodeGoaway(h2.lastPeerSid, H2NoError))
    h2.state = CsClosed
    h2.conn.close()
  s.conns.clear()
  s.tcp.close()
