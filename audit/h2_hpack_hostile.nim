## audit/h2_hpack_hostile.nim
##
## H2 HPACK decoder vs hostile integer/string/index representations
## (RFC 7541 §5.1, §6). Every malformed input must raise `HpackError` —
## never `IndexDefect`, never an unbounded allocation, never a hang.
##
## Red: any input below escapes as a Defect, allocates >4 MB, or hangs.
## Green: all raise HpackError promptly.

import powpow/proto/hpack
import std/unittest

template expectHpackError(body: untyped) =
  ## Passes iff body raises HpackError. Any other exception (notably
  ## IndexDefect/RangeDefect from table/buffer indexing) propagates and
  ## fails the test — that is the finding.
  var raised = false
  try:
    body
  except HpackError:
    raised = true
  check raised

suite "hpack hostile representations raise HpackError":

  test "indexed field with index 0 (reserved)":
    var ctx = newHpackContext()
    expectHpackError:
      discard ctx.decode(@[0x80'u8])

  test "indexed field beyond static table, empty dynamic table":
    var ctx = newHpackContext()
    expectHpackError:
      discard ctx.decode(@[0xBE'u8])  # indexed, idx 62 > 61 static

  test "indexed field with huge multi-byte index":
    var ctx = newHpackContext()
    # 0xFF (prefix max) + 5 continuation bytes, still huge.
    expectHpackError:
      discard ctx.decode(@[0xFF'u8, 0x80, 0x80, 0x80, 0x80, 0x7F])

  test "truncated integer (prefix max, no continuation)":
    var ctx = newHpackContext()
    expectHpackError:
      discard ctx.decode(@[0xFF'u8])

  test "overlong integer (6 continuation bytes)":
    var ctx = newHpackContext()
    expectHpackError:
      discard ctx.decode(@[0xFF'u8, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00])

  test "integer with bits past 32 (too large)":
    var ctx = newHpackContext()
    # m>=31 with nonzero payload bits must not overflow the accumulator.
    expectHpackError:
      discard ctx.decode(@[0xFF'u8, 0x80, 0x80, 0x80, 0x80, 0x0F])

  test "literal with incremental indexing, out-of-range name index":
    var ctx = newHpackContext()
    # 0x7F: literal+indexing, name idx prefix max(63) + continuation idx 200.
    expectHpackError:
      discard ctx.decode(@[0x7F'u8, 0x89, 0x01, 0x00, 0x01, byte('v')])

  test "literal without indexing, truncated string":
    var ctx = newHpackContext()
    # 0x00 new name, length 5, only 2 bytes present.
    expectHpackError:
      discard ctx.decode(@[0x00'u8, 0x05, byte('a'), byte('b')])

  test "string length just over 4 MB raises before allocating":
    var ctx = newHpackContext()
    # new name, raw string, length 4194305 = 0x400001 (base128: 81 80 80 02).
    expectHpackError:
      discard ctx.decode(@[0x00'u8, 0x7F, 0x81, 0x80, 0x80, 0x02])

  test "string length with 6 continuation bytes (too long)":
    var ctx = newHpackContext()
    expectHpackError:
      discard ctx.decode(@[0x00'u8, 0x7F, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00])

  test "truncated block mid-header (ends after prefix byte)":
    var ctx = newHpackContext()
    expectHpackError:
      discard ctx.decode(@[0x40'u8])  # literal+indexing, nothing follows

  test "empty block decodes to no headers":
    var ctx = newHpackContext()
    check ctx.decode(newSeq[byte]()) == newSeq[HpackHeader]()

  test "valid indexed reference still works (control)":
    var ctx = newHpackContext()
    let hs = ctx.decode(@[0x82'u8])  # :method: GET
    check hs.len == 1
    check hs[0].name == ":method"
    check hs[0].value == "GET"
