## tests/test_http2_frames.nim — HTTP/2 frame codec tests (RFC 7540 section 4, 6).

import ../src/powpow/proto/http2
import std/unittest

proc feedAll(data: openArray[byte]): seq[H2Frame] =
  var p = newH2FrameParser()
  p.feed(data)

test "settings_roundtrip":
  let bytes = encodeSettings([H2Setting(id: 3, value: 100),
                              H2Setting(id: 4, value: 65535)])
  let frames = feedAll(bytes)
  check frames.len == 1
  check frames[0].rawType == 4
  check frames[0].streamId == 0
  let settings = frames[0].decodeSettings()
  check settings.len == 2
  check settings[0].id == 3 and settings[0].value == 100
  check settings[1].id == 4 and settings[1].value == 65535

test "settings_ack_empty":
  let frames = feedAll(encodeSettingsAck())
  check frames.len == 1
  check (frames[0].flags and H2FlagAck) != 0
  check frames[0].decodeSettings().len == 0

test "ping_roundtrip":
  let opaque: array[8, byte] = [1'u8, 2, 3, 4, 5, 6, 7, 8]
  let frames = feedAll(encodePing(opaque))
  check frames.len == 1
  check frames[0].rawType == 6
  check frames[0].decodePing() == opaque
  let ack = feedAll(encodePingAck(opaque))
  check (ack[0].flags and H2FlagAck) != 0
  check ack[0].decodePing() == opaque

test "data_headers_roundtrip":
  let d = feedAll(encodeData(1, [byte('h'), byte('i')], endStream = true))
  check d.len == 1
  check d[0].rawType == 0 and d[0].streamId == 1
  check (d[0].flags and H2FlagEndStream) != 0
  check d[0].payload == @[byte('h'), byte('i')]
  let h = feedAll(encodeHeaders(3, [0x88'u8], endStream = false))
  check h.len == 1
  check h[0].rawType == 1 and h[0].streamId == 3
  check (h[0].flags and H2FlagEndHeaders) != 0

test "rst_stream_goaway_window_update_priority":
  let r = feedAll(encodeRstStream(1, H2Cancelled))
  check r[0].decodeRstStream() == H2Cancelled
  let w = feedAll(encodeWindowUpdate(0, 1024))
  check w[0].decodeWindowUpdate() == 1024
  let g = feedAll(encodeGoaway(5, H2NoError))
  let (lastSid, code, debugData) = g[0].decodeGoaway()
  check lastSid == 5 and code == H2NoError and debugData.len == 0
  let p = feedAll(encodePriority(1, 0, 16))
  let (excl, dep, weight) = p[0].decodePriority()
  check excl == false and dep == 0 and weight == 16

test "incremental_split_header":
  let bytes = encodePing([9'u8, 9, 9, 9, 9, 9, 9, 9])
  var p = newH2FrameParser()
  check p.feed(bytes.toOpenArray(0, 3)).len == 0
  check p.pendingBytes() == 4
  let rest = p.feed(bytes.toOpenArray(4, bytes.len - 1))
  check rest.len == 1
  check rest[0].rawType == 6

test "unknown_frame_type_ignored":
  let bytes = encodeFrame(99, 0, 1, [1'u8, 2, 3])
  let frames = feedAll(bytes)
  check frames.len == 1
  check frames[0].rawType == 99
  check frames[0].payload == @[1'u8, 2, 3]

test "rejects_data_on_stream_zero":
  let bytes = encodeFrame(0, 0, 0, [1'u8])
  var p = newH2FrameParser()
  expect H2Error:
    discard p.feed(bytes)

test "rejects_ping_wrong_length":
  let bytes = encodeFrame(6, 0, 0, [1'u8, 2])
  var p = newH2FrameParser()
  try:
    discard p.feed(bytes)
    check false
  except H2Error as e:
    check e.code == H2FrameSizeError

test "rejects_settings_on_stream":
  let bytes = encodeFrame(4, 0, 1, [])
  var p = newH2FrameParser()
  try:
    discard p.feed(bytes)
    check false
  except H2Error as e:
    check e.code == H2ProtocolError

test "rejects_oversize_frame":
  var p = newH2FrameParser(maxFrameSize = 16384)
  var big = newSeq[byte](16385)
  let bytes = encodeFrame(0, 0, 1, big)
  try:
    discard p.feed(bytes)
    check false
  except H2Error as e:
    check e.code == H2FrameSizeError

test "rejects_window_update_zero":
  let bytes = encodeFrame(8, 0, 0, [0'u8, 0, 0, 0])
  let frames = feedAll(bytes)
  try:
    discard frames[0].decodeWindowUpdate()
    check false
  except H2Error as e:
    check e.code == H2ProtocolError
