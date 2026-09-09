## tests/test_hpack.nim — HPACK codec tests (RFC 7541, Appendices C.1–C.6).

import ../src/powpow/proto/hpack
import std/unittest

proc hx(s: string): seq[byte] =
  ## Hex string to bytes.
  assert s.len mod 2 == 0
  result = newSeq[byte](s.len div 2)
  const digits = "0123456789abcdef"
  for i in 0 ..< result.len:
    let hi = digits.find(s[2*i])
    let lo = digits.find(s[2*i+1])
    assert hi >= 0 and lo >= 0
    result[i] = byte(hi * 16 + lo)

proc names(hs: seq[HpackHeader]): seq[string] =
  for h in hs: result.add(h.name & ": " & h.value)

test "c1_integer_examples":
  check encodeInt(10, 5, 0x00'u8) == @[0x0A'u8]
  check encodeInt(1337, 5, 0x00'u8) == @[0x1F'u8, 0x9A'u8, 0x0A'u8]
  check encodeInt(42, 8, 0x00'u8) == @[0x2A'u8]
  let (v1, n1) = decodeInt(@[0x0A'u8], 0, 5)
  check v1 == 10 and n1 == 1
  let (v2, n2) = decodeInt(@[0x1F'u8, 0x9A'u8, 0x0A'u8], 0, 5)
  check v2 == 1337 and n2 == 3
  let (v3, n3) = decodeInt(@[0x2A'u8], 0, 8)
  check v3 == 42 and n3 == 1

test "c2_representations":
  # C.2.4 indexed :method GET.
  var ctx = newHpackContext()
  check ctx.decode(hx("82")).names == @[":method: GET"]
  # C.2.1 literal with indexing, new name.
  ctx = newHpackContext()
  check ctx.decode(hx("400a637573746f6d2d6b65790d637573746f6d2d686561646572")).names ==
    @["custom-key: custom-header"]
  check ctx.table.len == 1  # inserted
  # C.2.2 literal without indexing, indexed name :path.
  ctx = newHpackContext()
  let hs = ctx.decode(hx("040c2f73616d706c652f70617468"))
  check hs.names == @[":path: /sample/path"]
  check ctx.table.len == 0  # not inserted
  # C.2.3 never indexed.
  ctx = newHpackContext()
  let hn = ctx.decode(hx("100870617373776f726406736563726574"))
  check hn.names == @["password: secret"]
  check hn[0].neverIndexed
  check ctx.table.len == 0

test "c3_requests_without_huffman":
  var ctx = newHpackContext()
  check ctx.decode(hx("828684410f7777772e6578616d706c652e636f6d")).names ==
    @[":method: GET", ":scheme: http", ":path: /",
      ":authority: www.example.com"]
  check ctx.decode(hx("828684be58086e6f2d6361636865")).names ==
    @[":method: GET", ":scheme: http", ":path: /",
      ":authority: www.example.com", "cache-control: no-cache"]
  check ctx.decode(hx("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565")).names ==
    @[":method: GET", ":scheme: https", ":path: /index.html",
      ":authority: www.example.com", "custom-key: custom-value"]
  check ctx.tableSize <= 4096

test "c4_requests_with_huffman":
  var ctx = newHpackContext()
  check ctx.decode(hx("828684418cf1e3c2e5f23a6ba0ab90f4ff")).names ==
    @[":method: GET", ":scheme: http", ":path: /",
      ":authority: www.example.com"]
  check ctx.decode(hx("828684be5886a8eb10649cbf")).names ==
    @[":method: GET", ":scheme: http", ":path: /",
      ":authority: www.example.com", "cache-control: no-cache"]
  check ctx.decode(hx("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf")).names ==
    @[":method: GET", ":scheme: https", ":path: /index.html",
      ":authority: www.example.com", "custom-key: custom-value"]

test "c5_first_response_without_huffman":
  var ctx = newHpackContext()
  check ctx.decode(hx("4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d")).names ==
    @[":status: 302", "cache-control: private",
      "date: Mon, 21 Oct 2013 20:13:21 GMT",
      "location: https://www.example.com"]

test "c6_first_response_with_huffman":
  var ctx = newHpackContext()
  check ctx.decode(hx("488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3")).names ==
    @[":status: 302", "cache-control: private",
      "date: Mon, 21 Oct 2013 20:13:21 GMT",
      "location: https://www.example.com"]

test "huffman_roundtrip_all_bytes":
  var s = newString(256)
  for i in 0 .. 255: s[i] = char(i)
  check huffmanDecode(huffmanEncode(s)) == s
  check huffmanDecode(huffmanEncode("www.example.com")) == "www.example.com"
  check huffmanDecode(huffmanEncode("custom-key")) == "custom-key"
  check huffmanDecode(huffmanEncode("")) == ""

test "huffman_known_vectors":
  # C.4.1: "www.example.com" Huffman bytes (length 12, H=1).
  check huffmanDecode(hx("f1e3c2e5f23a6ba0ab90f4ff")) == "www.example.com"
  # C.4.2: "no-cache" Huffman bytes (length 6, H=1).
  check huffmanDecode(hx("a8eb10649cbf")) == "no-cache"
  # Encoder must pick Huffman when shorter.
  check huffmanEncode("www.example.com") == hx("f1e3c2e5f23a6ba0ab90f4ff")

test "huffman_rejects_eos_and_bad_padding":
  # 30 ones = EOS code.
  expect HpackError:
    discard huffmanDecode(@[0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8])
  # 8 zero bits: invalid code path.
  expect HpackError:
    discard huffmanDecode(@[0x00'u8])
  # 8 ones: padding longer than 7 bits.
  expect HpackError:
    discard huffmanDecode(@[0xFF'u8])

test "decoder_rejects_bad_index":
  var ctx = newHpackContext()
  expect HpackError:  # index 0 reserved
    discard ctx.decode(@[0x80'u8])
  expect HpackError:  # index beyond tables
    discard ctx.decode(@[0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0x07'u8])
  expect HpackError:  # truncated block
    discard ctx.decode(@[0x41'u8])

test "table_size_update_and_eviction":
  var ctx = newHpackContext()
  discard ctx.decode(hx("828684410f7777772e6578616d706c652e636f6d"))
  check ctx.table.len == 1
  # Shrink to 0 via size update (0x20): drains the table.
  discard ctx.decode(@[0x20'u8])
  check ctx.table.len == 0
  check ctx.tableSize == 0
  # Update beyond the protocol limit is an error (4097 > 4096).
  expect HpackError:
    discard ctx.decode(@[0x3F'u8, 0xE2'u8, 0x1F'u8])
  # Oversized entry (10 + 28 + 32 = 70 > 64) drains instead of inserting.
  var bigEnc = newHpackContext()
  let bigWire = bigEnc.encode(@[HpackHeader(name: "custom-key",
    value: "0123456789012345678901234567")])
  var small = newHpackContext(maxTableSize = 64, maxAllowedSize = 64)
  let gotBig = small.decode(bigWire)
  check gotBig.names == @["custom-key: 0123456789012345678901234567"]
  check small.table.len == 0

test "encoder_decoder_roundtrip":
  var enc = newHpackContext()
  var dec = newHpackContext()
  let batch1 = @[HpackHeader(name: ":method", value: "GET"),
                 HpackHeader(name: ":scheme", value: "https"),
                 HpackHeader(name: ":path", value: "/index.html"),
                 HpackHeader(name: ":authority", value: "www.example.com"),
                 HpackHeader(name: "custom-key", value: "custom-value")]
  let wire1 = enc.encode(batch1)
  check dec.decode(wire1).names == batch1.names
  # Second batch reuses dynamic entries via indexed fields.
  let batch2 = @[HpackHeader(name: ":method", value: "GET"),
                 HpackHeader(name: ":scheme", value: "https"),
                 HpackHeader(name: ":path", value: "/index.html"),
                 HpackHeader(name: ":authority", value: "www.example.com"),
                 HpackHeader(name: "cache-control", value: "no-cache")]
  let wire2 = enc.encode(batch2)
  check dec.decode(wire2).names == batch2.names
  check enc.tableSize == dec.tableSize
  # Never-indexed survives a roundtrip without table insertion.
  let batch3 = @[HpackHeader(name: "authorization", value: "secret",
                             neverIndexed: true)]
  let wire3 = enc.encode(batch3)
  let got3 = dec.decode(wire3)
  check got3.names == batch3.names
  check got3[0].neverIndexed
  # Raw (no-Huffman) encoding also roundtrips on a fresh pair.
  var dec2 = newHpackContext()
  var enc2 = newHpackContext()
  let wire4 = enc2.encode(batch1, useHuffman = false)
  check dec2.decode(wire4).names == batch1.names
