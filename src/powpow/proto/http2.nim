# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/proto/http2.nim — HTTP/2 binary framing layer (RFC 7540 section 4, 6).
##
## Pure codec with no I/O: an incremental `H2FrameParser` decoding the 9-byte
## frame header plus payload, and `encode*` helpers for every frame type the
## M1 milestone needs. Stream state, HPACK, and flow control live elsewhere
## (`H2Conn`, `proto/hpack`); this module only validates frame-level rules:
## stream-zero discipline, fixed-length frames, and `SETTINGS_MAX_FRAME_SIZE`.
##
## Unknown frame types are returned (not dropped) so callers can ignore them
## per RFC 7540 section 5.5. Connection-level violations raise `H2Error`
## carrying an `H2ErrorCode`.

type
  H2FrameType* = enum
    H2Data = 0
    H2Headers = 1
    H2Priority = 2
    H2RstStream = 3
    H2Settings = 4
    H2PushPromise = 5
    H2Ping = 6
    H2Goaway = 7
    H2WindowUpdate = 8
    H2Continuation = 9

  H2ErrorCode* = enum
    H2NoError = 0
    H2ProtocolError = 1
    H2InternalError = 2
    H2FlowControlError = 3
    H2SettingsTimeout = 4
    H2StreamClosed = 5
    H2FrameSizeError = 6
    H2RefusedStream = 7
    H2Cancelled = 8
    H2CompressionError = 9
    H2ConnectError = 10
    H2EnhanceYourCalm = 11
    H2InadequateSecurity = 12
    H2Http11Required = 13

  H2SettingsId* = enum
    H2HeaderTableSize = 1
    H2EnablePush = 2
    H2MaxConcurrentStreams = 3
    H2InitialWindowSize = 4
    H2MaxFrameSize = 5
    H2MaxHeaderListSize = 6

  H2Error* = object of CatchableError
    code*: H2ErrorCode

  H2Frame* = object
    ## One decoded frame. `payload` is the raw frame body (padding already
    ## stripped for PADDED DATA/HEADERS); `rawType` preserves unknown types.
    typ*: H2FrameType
    rawType*: int
    flags*: uint8
    streamId*: int32
    payload*: seq[byte]

  H2Setting* = object
    id*: uint16
    value*: uint32

  H2FrameParser* = object
    buf*: seq[byte]
    maxFrameSize*: int

const
  H2FrameHeaderLen* = 9
  H2DefaultMaxFrameSize* = 16384
  H2MaxFrameSizeMin* = 16384
  H2MaxFrameSizeMax* = 16777215
  H2DefaultWindowSize* = 65535
  H2MaxWindowSize* = 2147483647

  H2ConnectionPreface* = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  # Flags
  H2FlagAck* = 0x01'u8
  H2FlagEndStream* = 0x01'u8
  H2FlagEndHeaders* = 0x04'u8
  H2FlagPadded* = 0x08'u8
  H2FlagPriority* = 0x20'u8

proc h2Error(code: H2ErrorCode, msg: string): ref H2Error =
  result = newException(H2Error, msg)
  result.code = code

proc newH2FrameParser*(maxFrameSize = H2DefaultMaxFrameSize): H2FrameParser =
  H2FrameParser(buf: @[], maxFrameSize: maxFrameSize)

proc frameTypeFromInt*(v: int): tuple[known: bool, typ: H2FrameType] =
  case v
  of 0: (true, H2Data)
  of 1: (true, H2Headers)
  of 2: (true, H2Priority)
  of 3: (true, H2RstStream)
  of 4: (true, H2Settings)
  of 5: (true, H2PushPromise)
  of 6: (true, H2Ping)
  of 7: (true, H2Goaway)
  of 8: (true, H2WindowUpdate)
  of 9: (true, H2Continuation)
  else: (false, H2Data)

proc stripPadding(payload: openArray[byte], padded: bool): seq[byte] =
  if not padded:
    result = newSeq[byte](payload.len)
    for i in 0 ..< payload.len:
      result[i] = payload[i]
    return
  if payload.len < 1:
    raise h2Error(H2ProtocolError, "h2: PADDED flag with empty payload")
  let padLen = int(payload[0])
  if padLen + 1 > payload.len:
    raise h2Error(H2ProtocolError, "h2: padding exceeds payload")
  let bodyLen = payload.len - 1 - padLen
  result = newSeq[byte](bodyLen)
  for i in 0 ..< bodyLen:
    result[i] = payload[1 + i]

proc validateFrame(typ: int, known: bool, flags: uint8, streamId: int32,
                   length: int, maxFrameSize: int) =
  if length > maxFrameSize:
    raise h2Error(H2FrameSizeError, "h2: frame exceeds SETTINGS_MAX_FRAME_SIZE")
  if length > H2MaxFrameSizeMax:
    raise h2Error(H2FrameSizeError, "h2: frame exceeds protocol maximum")
  if not known:
    return  # extension frames: only size bounds apply (RFC 7540 5.5)
  case typ
  of 0: # DATA
    if streamId == 0:
      raise h2Error(H2ProtocolError, "h2: DATA on stream 0")
  of 1: # HEADERS
    if streamId == 0:
      raise h2Error(H2ProtocolError, "h2: HEADERS on stream 0")
  of 2: # PRIORITY
    if streamId == 0:
      raise h2Error(H2ProtocolError, "h2: PRIORITY on stream 0")
    if length != 5:
      raise h2Error(H2FrameSizeError, "h2: PRIORITY length must be 5")
  of 3: # RST_STREAM
    if streamId == 0:
      raise h2Error(H2ProtocolError, "h2: RST_STREAM on stream 0")
    if length != 4:
      raise h2Error(H2FrameSizeError, "h2: RST_STREAM length must be 4")
  of 4: # SETTINGS
    if streamId != 0:
      raise h2Error(H2ProtocolError, "h2: SETTINGS on non-zero stream")
    if (flags and H2FlagAck) != 0:
      if length != 0:
        raise h2Error(H2FrameSizeError, "h2: SETTINGS ACK must be empty")
    elif length mod 6 != 0:
      raise h2Error(H2FrameSizeError, "h2: SETTINGS length must be multiple of 6")
  of 5: # PUSH_PROMISE (deferred: caller treats as PROTOCOL_ERROR)
    if streamId == 0:
      raise h2Error(H2ProtocolError, "h2: PUSH_PROMISE on stream 0")
  of 6: # PING
    if streamId != 0:
      raise h2Error(H2ProtocolError, "h2: PING on non-zero stream")
    if length != 8:
      raise h2Error(H2FrameSizeError, "h2: PING length must be 8")
  of 7: # GOAWAY
    if streamId != 0:
      raise h2Error(H2ProtocolError, "h2: GOAWAY on non-zero stream")
    if length < 8:
      raise h2Error(H2FrameSizeError, "h2: GOAWAY length must be >= 8")
  of 8: # WINDOW_UPDATE
    if length != 4:
      raise h2Error(H2FrameSizeError, "h2: WINDOW_UPDATE length must be 4")
  of 9: # CONTINUATION
    if streamId == 0:
      raise h2Error(H2ProtocolError, "h2: CONTINUATION on stream 0")
  else: discard

proc feed*(p: var H2FrameParser, data: openArray[byte]): seq[H2Frame] =
  ## Append `data`, return every complete frame available. Raises `H2Error`
  ## on connection-level framing violations. Unconsumed bytes stay buffered.
  let oldLen = p.buf.len
  p.buf.setLen(oldLen + data.len)
  for i in 0 ..< data.len:
    p.buf[oldLen + i] = data[i]
  result = @[]
  while true:
    if p.buf.len < H2FrameHeaderLen:
      return
    let length = (int(p.buf[0]) shl 16) or (int(p.buf[1]) shl 8) or int(p.buf[2])
    let typInt = int(p.buf[3])
    let flags = p.buf[4]
    let streamId = int32((int(p.buf[5]) and 0x7F) shl 24 or
                         (int(p.buf[6]) shl 16) or
                         (int(p.buf[7]) shl 8) or int(p.buf[8]))
    if (p.buf[5] and 0x80) != 0:
      raise h2Error(H2ProtocolError, "h2: reserved bit must be zero")
    let (known, typ) = frameTypeFromInt(typInt)
    validateFrame(typInt, known, flags, streamId, length, p.maxFrameSize)
    if p.buf.len < H2FrameHeaderLen + length:
      return  # wait for the full payload
    var payload = newSeq[byte](length)
    for i in 0 ..< length:
      payload[i] = p.buf[H2FrameHeaderLen + i]
    # Strip padding for DATA / HEADERS before delivery.
    if known and (typ == H2Data or typ == H2Headers):
      if (flags and H2FlagPadded) != 0:
        payload = stripPadding(payload, true)
    let frameTyp = if known: typ else: H2Data
    result.add(H2Frame(typ: frameTyp, rawType: typInt, flags: flags,
                       streamId: streamId, payload: payload))
    let consumed = H2FrameHeaderLen + length
    if consumed < p.buf.len:
      let remaining = p.buf.len - consumed
      for i in 0 ..< remaining:
        p.buf[i] = p.buf[consumed + i]
      p.buf.setLen(remaining)
    else:
      p.buf.setLen(0)

proc pendingBytes*(p: H2FrameParser): int {.inline.} =
  p.buf.len

# ── Payload decoders ────────────────────────────────────────────────────

proc decodeSettings*(f: H2Frame): seq[H2Setting] =
  if f.rawType != 4:
    raise h2Error(H2ProtocolError, "h2: not a SETTINGS frame")
  if (f.flags and H2FlagAck) != 0:
    if f.payload.len != 0:
      raise h2Error(H2FrameSizeError, "h2: SETTINGS ACK must be empty")
    return @[]
  if f.payload.len mod 6 != 0:
    raise h2Error(H2FrameSizeError, "h2: SETTINGS length must be multiple of 6")
  result = newSeq[H2Setting](f.payload.len div 6)
  for i in 0 ..< result.len:
    let o = i * 6
    result[i] = H2Setting(
      id: uint16((uint16(f.payload[o]) shl 8) or uint16(f.payload[o+1])),
      value: (uint32(f.payload[o+2]) shl 24) or (uint32(f.payload[o+3]) shl 16) or
             (uint32(f.payload[o+4]) shl 8) or uint32(f.payload[o+5]))

proc decodePing*(f: H2Frame): array[8, byte] =
  if f.rawType != 6 or f.payload.len != 8:
    raise h2Error(H2FrameSizeError, "h2: PING length must be 8")
  for i in 0 ..< 8: result[i] = f.payload[i]

proc decodeRstStream*(f: H2Frame): H2ErrorCode =
  if f.rawType != 3 or f.payload.len != 4:
    raise h2Error(H2FrameSizeError, "h2: RST_STREAM length must be 4")
  let v = (uint32(f.payload[0]) shl 24) or (uint32(f.payload[1]) shl 16) or
          (uint32(f.payload[2]) shl 8) or uint32(f.payload[3])
  if v <= 13: H2ErrorCode(v) else: H2InternalError

proc decodeWindowUpdate*(f: H2Frame): uint32 =
  if f.rawType != 8 or f.payload.len != 4:
    raise h2Error(H2FrameSizeError, "h2: WINDOW_UPDATE length must be 4")
  result = ((uint32(f.payload[0]) and 0x7F) shl 24) or
           (uint32(f.payload[1]) shl 16) or
           (uint32(f.payload[2]) shl 8) or uint32(f.payload[3])
  if result == 0:
    raise h2Error(H2ProtocolError, "h2: WINDOW_UPDATE increment must be non-zero")
  if result > uint32(H2MaxWindowSize):
    raise h2Error(H2FlowControlError, "h2: WINDOW_UPDATE increment too large")

proc decodeGoaway*(f: H2Frame): tuple[lastStreamId: int32, code: H2ErrorCode,
                                      debugData: seq[byte]] =
  if f.rawType != 7 or f.payload.len < 8:
    raise h2Error(H2FrameSizeError, "h2: GOAWAY length must be >= 8")
  let lastSid = int32(((uint32(f.payload[0]) and 0x7F) shl 24) or
                      (uint32(f.payload[1]) shl 16) or
                      (uint32(f.payload[2]) shl 8) or uint32(f.payload[3]))
  let cv = (uint32(f.payload[4]) shl 24) or (uint32(f.payload[5]) shl 16) or
           (uint32(f.payload[6]) shl 8) or uint32(f.payload[7])
  let code = if cv <= 13: H2ErrorCode(cv) else: H2InternalError
  let debugData = if f.payload.len > 8: f.payload[8 .. ^1] else: @[]
  (lastSid, code, debugData)

proc decodePriority*(f: H2Frame): tuple[exclusive: bool, depId: int32,
                                       weight: uint8] =
  if f.rawType != 2 or f.payload.len != 5:
    raise h2Error(H2FrameSizeError, "h2: PRIORITY length must be 5")
  let exclusive = (f.payload[0] and 0x80) != 0
  let depId = int32(((uint32(f.payload[0]) and 0x7F) shl 24) or
                    (uint32(f.payload[1]) shl 16) or
                    (uint32(f.payload[2]) shl 8) or uint32(f.payload[3]))
  (exclusive, depId, f.payload[4])

# ── Encoders ────────────────────────────────────────────────────────────

proc encodeFrame*(typ: int, flags: uint8, streamId: int32,
                  payload: openArray[byte]): seq[byte] =
  result = newSeq[byte](H2FrameHeaderLen + payload.len)
  result[0] = byte((payload.len shr 16) and 0xFF)
  result[1] = byte((payload.len shr 8) and 0xFF)
  result[2] = byte(payload.len and 0xFF)
  result[3] = byte(typ and 0xFF)
  result[4] = flags
  result[5] = byte((streamId shr 24) and 0x7F)  # reserved bit stays zero
  result[6] = byte((streamId shr 16) and 0xFF)
  result[7] = byte((streamId shr 8) and 0xFF)
  result[8] = byte(streamId and 0xFF)
  for i in 0 ..< payload.len:
    result[H2FrameHeaderLen + i] = payload[i]

proc encodeSettings*(settings: openArray[H2Setting]): seq[byte] =
  var payload = newSeq[byte](settings.len * 6)
  for i, s in settings:
    payload[i*6] = byte((s.id shr 8) and 0xFF)
    payload[i*6+1] = byte(s.id and 0xFF)
    payload[i*6+2] = byte((s.value shr 24) and 0xFF)
    payload[i*6+3] = byte((s.value shr 16) and 0xFF)
    payload[i*6+4] = byte((s.value shr 8) and 0xFF)
    payload[i*6+5] = byte(s.value and 0xFF)
  encodeFrame(4, 0, 0, payload)

proc encodeSettingsAck*(): seq[byte] =
  encodeFrame(4, H2FlagAck, 0, [])

proc encodePing*(opaqueData: array[8, byte]): seq[byte] =
  encodeFrame(6, 0, 0, opaqueData)

proc encodePingAck*(opaqueData: array[8, byte]): seq[byte] =
  encodeFrame(6, H2FlagAck, 0, opaqueData)

proc encodeWindowUpdate*(streamId: int32, increment: uint32): seq[byte] =
  if increment == 0 or increment > uint32(H2MaxWindowSize):
    raise h2Error(H2FlowControlError, "h2: bad WINDOW_UPDATE increment")
  let payload = [byte((increment shr 24) and 0x7F), byte((increment shr 16) and 0xFF),
                 byte((increment shr 8) and 0xFF), byte(increment and 0xFF)]
  encodeFrame(8, 0, streamId, payload)

proc encodeRstStream*(streamId: int32, code: H2ErrorCode): seq[byte] =
  if streamId == 0:
    raise h2Error(H2ProtocolError, "h2: RST_STREAM on stream 0")
  let v = uint32(ord(code))
  let payload = [byte((v shr 24) and 0xFF), byte((v shr 16) and 0xFF),
                 byte((v shr 8) and 0xFF), byte(v and 0xFF)]
  encodeFrame(3, 0, streamId, payload)

proc encodeGoaway*(lastStreamId: int32, code: H2ErrorCode,
                   debugData: openArray[byte] = []): seq[byte] =
  var payload = newSeq[byte](8 + debugData.len)
  payload[0] = byte((lastStreamId shr 24) and 0x7F)
  payload[1] = byte((lastStreamId shr 16) and 0xFF)
  payload[2] = byte((lastStreamId shr 8) and 0xFF)
  payload[3] = byte(lastStreamId and 0xFF)
  let v = uint32(ord(code))
  payload[4] = byte((v shr 24) and 0xFF)
  payload[5] = byte((v shr 16) and 0xFF)
  payload[6] = byte((v shr 8) and 0xFF)
  payload[7] = byte(v and 0xFF)
  for i in 0 ..< debugData.len:
    payload[8 + i] = debugData[i]
  encodeFrame(7, 0, 0, payload)

proc encodeData*(streamId: int32, data: openArray[byte],
                 endStream = false): seq[byte] =
  if streamId == 0:
    raise h2Error(H2ProtocolError, "h2: DATA on stream 0")
  encodeFrame(0, if endStream: H2FlagEndStream else: 0'u8, streamId, data)

proc encodeHeaders*(streamId: int32, headerBlock: openArray[byte],
                    endStream = false, endHeaders = true): seq[byte] =
  if streamId == 0:
    raise h2Error(H2ProtocolError, "h2: HEADERS on stream 0")
  var flags: uint8 = 0
  if endStream: flags = flags or H2FlagEndStream
  if endHeaders: flags = flags or H2FlagEndHeaders
  encodeFrame(1, flags, streamId, headerBlock)

proc encodePriority*(streamId, depId: int32, weight: uint8,
                     exclusive = false): seq[byte] =
  if streamId == 0:
    raise h2Error(H2ProtocolError, "h2: PRIORITY on stream 0")
  var payload = newSeq[byte](5)
  payload[0] = byte((depId shr 24) and 0x7F)
  if exclusive: payload[0] = payload[0] or 0x80
  payload[1] = byte((depId shr 16) and 0xFF)
  payload[2] = byte((depId shr 8) and 0xFF)
  payload[3] = byte(depId and 0xFF)
  payload[4] = weight
  encodeFrame(2, 0, streamId, payload)
