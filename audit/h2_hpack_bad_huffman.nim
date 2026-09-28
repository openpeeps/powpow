## audit/h2_hpack_bad_huffman.nim
##
## H2 Huffman string decoder vs invalid/truncated/padded inputs
## (RFC 7541 §5.2). Must raise `HpackError` on EOS codes, invalid codes,
## overlong or non-ones padding — never index out of the decode tree,
## never emit unbounded output, never hang.
##
## Red: any input below escapes as a Defect, loops, or over-allocates.
## Green: all raise HpackError promptly (roundtrip control passes).

import powpow/proto/hpack
import std/[strutils, unittest]

template expectHpackError(body: untyped) =
  var raised = false
  try:
    body
  except HpackError:
    raised = true
  check raised

suite "huffman decoder rejects hostile strings":

  test "roundtrip control":
    let enc = huffmanEncode("hello world")
    check huffmanDecode(enc) == "hello world"

  test "single 0xFF byte (EOS code)":
    expectHpackError:
      discard huffmanDecode(@[0xFF'u8])

  test "EOS prefix then trailing bits":
    # 0xFF 0xFF...: EOS hit on the first octet regardless of the tail.
    expectHpackError:
      discard huffmanDecode(@[0xFF'u8, 0x00])

  test "zero byte (decodes '0' then zero padding, not ones)":
    # 0x00 = code 00000 ('0') + 000 padding: padding must be all ones.
    expectHpackError:
      discard huffmanDecode(@[0x00'u8])

  test "valid symbol plus zero padding":
    # '0' (00000) then 3 zero pad bits: padding must be all ones.
    let enc = huffmanEncode("0")
    check enc.len == 1
    expectHpackError:
      discard huffmanDecode(@[(enc[0] and 0xF8'u8)])

  test "ones-padding is indistinguishable from truncation (accepts)":
    # 0x1F = 'a' (00011) + 111 padding: per RFC 7541 §5.2 a decoder cannot
    # tell this apart from a truncated stream, so it MUST accept and emit "a".
    # Pinned as correct leniency, not a finding.
    check huffmanDecode(@[0x1F'u8]) == "a"

  test "truncated multi-byte with zero tail raises":
    # 0x1F ('a' + pad) then 0x00: next code 00000 ('0') + 000 padding —
    # non-ones padding must raise.
    expectHpackError:
      discard huffmanDecode(@[0x1F'u8, 0x00])

  test "padding longer than 7 bits":
    # A full octet of ones after a complete symbol is 8 pad bits (> 7).
    let enc = huffmanEncode("a")
    var data = enc
    data.add(0xFF'u8)
    expectHpackError:
      discard huffmanDecode(data)

  test "empty input decodes to empty string":
    check huffmanDecode(newSeq[byte]()) == ""

  test "long valid string stays bounded":
    let big = huffmanEncode("abcdefghij".repeat(10000))
    check huffmanDecode(big).len == 100000
