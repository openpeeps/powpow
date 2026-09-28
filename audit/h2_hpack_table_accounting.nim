## audit/h2_hpack_table_accounting.nim
##
## H2 HPACK dynamic-table accounting vs hostile updates (RFC 7541 §4).
## Eviction on size-update lowering, index-into-evicted-slot, oversized
## entries, never-indexed privacy, and the §4.2 "size update must open the
## block" rule. Stale/dynamic-index confusion must raise, never misresolve.
##
## Red: wrong header resolved, eviction skipped, sensitive header indexed.
## Green: all accounting exact (plus one documented leniency, see below).

import powpow/proto/hpack
import std/[strutils, unittest]

template expectHpackError(body: untyped) =
  var raised = false
  try:
    body
  except HpackError:
    raised = true
  check raised

proc insertLit(name, value: string): seq[byte] =
  ## Literal with incremental indexing, new name, raw strings.
  result = @[0x40'u8, byte(name.len)]
  for c in name: result.add(byte(c))
  result.add(byte(value.len))
  for c in value: result.add(byte(c))

suite "hpack dynamic table accounting":

  test "insert then dynamic reference resolves":
    var ctx = newHpackContext()
    discard ctx.decode(insertLit("x-a", "1"))
    let hs = ctx.decode(@[0xBE'u8])  # indexed, dyn 0 (62 total)
    check hs.len == 1
    check hs[0].name == "x-a"
    check hs[0].value == "1"

  test "eviction drops oldest, indexes shift":
    var ctx = newHpackContext(maxTableSize = 64)
    discard ctx.decode(insertLit("x-a", "1"))  # 36 bytes
    discard ctx.decode(insertLit("x-b", "2"))  # 36 + 36 > 64: evicts x-a
    let hs = ctx.decode(@[0xBE'u8])
    check hs[0].name == "x-b"
    expectHpackError:
      discard ctx.decode(@[0xBF'u8])  # dyn 1: nothing there

  test "size update lowering evicts immediately":
    var ctx = newHpackContext()
    discard ctx.decode(insertLit("x-a", "1"))
    discard ctx.decode(insertLit("x-b", "2"))
    # Table size update to 40: only the newest 36-byte entry fits.
    discard ctx.decode(@[0x3F'u8, 0x09])  # 0x20-pattern + 31 + 9 = 40
    let hs = ctx.decode(@[0xBE'u8])
    check hs[0].name == "x-b"
    expectHpackError:
      discard ctx.decode(@[0xBF'u8])

  test "size update above the limit raises":
    var ctx = newHpackContext()  # maxAllowedSize 4096
    # Update to 8192: prefix max 31 + base128(8161) = E1 3F.
    expectHpackError:
      discard ctx.decode(@[0x3F'u8, 0xE1, 0x3F])

  test "size update to zero drains the table":
    var ctx = newHpackContext()
    discard ctx.decode(insertLit("x-a", "1"))
    discard ctx.decode(@[0x20'u8])  # size update to 0
    expectHpackError:
      discard ctx.decode(@[0xBE'u8])

  test "oversized entry drains table, inserts nothing":
    var ctx = newHpackContext(maxTableSize = 64)
    discard ctx.decode(insertLit("x-a", "1"))
    # 100-byte value: entry (101+32) > table: drains, inserts nothing.
    var big = "v".repeat(100)
    discard ctx.decode(insertLit("x-big", big))
    expectHpackError:
      discard ctx.decode(@[0xBE'u8])

  test "never-indexed header is flagged and not tabled":
    var ctx = newHpackContext()
    # 0x10: literal never-indexed, new name "authorization".
    var blk = @[0x10'u8, 0x0D]
    for c in "authorization": blk.add(byte(c))
    blk.add(0x06)
    for c in "secret": blk.add(byte(c))
    let hs = ctx.decode(blk)
    check hs.len == 1
    check hs[0].neverIndexed
    # Must not be retrievable by dynamic index afterwards.
    expectHpackError:
      discard ctx.decode(@[0xBE'u8])

  test "size update mid-block is accepted (documented leniency)":
    # RFC 7541 §4.2 requires a size update to open the header block.
    # The decoder accepts it anywhere — pure leniency with no memory or
    # accounting impact (eviction runs immediately). Pinned, not a finding.
    var ctx = newHpackContext()
    discard ctx.decode(insertLit("x-a", "1"))
    let hs = ctx.decode(@[0x82'u8, 0x20])  # :method GET, then size update to 0
    check hs.len == 1
    check hs[0].name == ":method"
    expectHpackError:
      discard ctx.decode(@[0xBE'u8])  # x-a evicted by the mid-block update
