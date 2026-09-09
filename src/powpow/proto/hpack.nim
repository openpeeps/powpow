# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/proto/hpack.nim — HPACK header compression (RFC 7541, full).
##
## Static table (Appendix A) + dynamic table with eviction, integer codec
## with prefix (§5.1), string literals with Huffman flag (§5.2), all four
## header field representations (§6.1–§6.2) and dynamic table size updates
## (§6.3), and the spec Huffman codec (Appendix B).
##
## `HpackContext` holds one direction's dynamic table: encoder and decoder
## each own one (they are independent per RFC 7541 §2.2). Decoding errors
## raise `HpackError`; callers map it to `COMPRESSION_ERROR`.

type
  HpackError* = object of CatchableError

  HpackHeader* = object
    name*: string
    value*: string
    neverIndexed*: bool

  HpackContext* = object
    table*: seq[HpackHeader]  ## Dynamic table, newest entry first.
    tableSize*: int           ## Sum of entry sizes (name+value+32 each).
    maxTableSize*: int        ## Current limit (evict beyond this).
    maxAllowedSize*: int      ## Protocol limit (SETTINGS_HEADER_TABLE_SIZE).
    lastSignaledSize*: int    ## Last size the encoder announced.

const
  HpackStaticTableLen* = 61
  HpackDefaultTableSize* = 4096
  HpackMaxStringLen* = 4 * 1024 * 1024

proc hpackError*(msg: string): ref HpackError =
  newException(HpackError, msg)

const hpackStaticTable: array[61, tuple[name, value: string]] = [
  (":authority", ""),
  (":method", "GET"),
  (":method", "POST"),
  (":path", "/"),
  (":path", "/index.html"),
  (":scheme", "http"),
  (":scheme", "https"),
  (":status", "200"),
  (":status", "204"),
  (":status", "206"),
  (":status", "304"),
  (":status", "400"),
  (":status", "404"),
  (":status", "500"),
  ("accept-charset", ""),
  ("accept-encoding", "gzip, deflate"),
  ("accept-language", ""),
  ("accept-ranges", ""),
  ("accept", ""),
  ("access-control-allow-origin", ""),
  ("age", ""),
  ("allow", ""),
  ("authorization", ""),
  ("cache-control", ""),
  ("content-disposition", ""),
  ("content-encoding", ""),
  ("content-language", ""),
  ("content-length", ""),
  ("content-location", ""),
  ("content-range", ""),
  ("content-type", ""),
  ("cookie", ""),
  ("date", ""),
  ("etag", ""),
  ("expect", ""),
  ("expires", ""),
  ("from", ""),
  ("host", ""),
  ("if-match", ""),
  ("if-modified-since", ""),
  ("if-none-match", ""),
  ("if-range", ""),
  ("if-unmodified-since", ""),
  ("last-modified", ""),
  ("link", ""),
  ("location", ""),
  ("max-forwards", ""),
  ("proxy-authenticate", ""),
  ("proxy-authorization", ""),
  ("range", ""),
  ("referer", ""),
  ("refresh", ""),
  ("retry-after", ""),
  ("server", ""),
  ("set-cookie", ""),
  ("strict-transport-security", ""),
  ("transfer-encoding", ""),
  ("user-agent", ""),
  ("vary", ""),
  ("via", ""),
  ("www-authenticate", ""),
]

# ── Huffman codec (RFC 7541 Appendix B) ────────────────────────────────
# Table: (code with the Huffman bits in the LOW `bits` positions, bit length).
# Index 256 is EOS.

const huffmanCodes: array[257, tuple[code: uint32, bits: uint8]] = [
  (0x1ff8'u32, 13'u8), (0x7fffd8'u32, 23'u8),
  (0xfffffe2'u32, 28'u8), (0xfffffe3'u32, 28'u8),
  (0xfffffe4'u32, 28'u8), (0xfffffe5'u32, 28'u8),
  (0xfffffe6'u32, 28'u8), (0xfffffe7'u32, 28'u8),
  (0xfffffe8'u32, 28'u8), (0xffffea'u32, 24'u8),
  (0x3ffffffc'u32, 30'u8), (0xfffffe9'u32, 28'u8),
  (0xfffffea'u32, 28'u8), (0x3ffffffd'u32, 30'u8),
  (0xfffffeb'u32, 28'u8), (0xfffffec'u32, 28'u8),
  (0xfffffed'u32, 28'u8), (0xfffffee'u32, 28'u8),
  (0xfffffef'u32, 28'u8), (0xffffff0'u32, 28'u8),
  (0xffffff1'u32, 28'u8), (0xffffff2'u32, 28'u8),
  (0x3ffffffe'u32, 30'u8), (0xffffff3'u32, 28'u8),
  (0xffffff4'u32, 28'u8), (0xffffff5'u32, 28'u8),
  (0xffffff6'u32, 28'u8), (0xffffff7'u32, 28'u8),
  (0xffffff8'u32, 28'u8), (0xffffff9'u32, 28'u8),
  (0xffffffa'u32, 28'u8), (0xffffffb'u32, 28'u8),
  (0x14'u32, 6'u8), (0x3f8'u32, 10'u8),
  (0x3f9'u32, 10'u8), (0xffa'u32, 12'u8),
  (0x1ff9'u32, 13'u8), (0x15'u32, 6'u8),
  (0xf8'u32, 8'u8), (0x7fa'u32, 11'u8),
  (0x3fa'u32, 10'u8), (0x3fb'u32, 10'u8),
  (0xf9'u32, 8'u8), (0x7fb'u32, 11'u8),
  (0xfa'u32, 8'u8), (0x16'u32, 6'u8),
  (0x17'u32, 6'u8), (0x18'u32, 6'u8),
  (0x0'u32, 5'u8), (0x1'u32, 5'u8),
  (0x2'u32, 5'u8), (0x19'u32, 6'u8),
  (0x1a'u32, 6'u8), (0x1b'u32, 6'u8),
  (0x1c'u32, 6'u8), (0x1d'u32, 6'u8),
  (0x1e'u32, 6'u8), (0x1f'u32, 6'u8),
  (0x5c'u32, 7'u8), (0xfb'u32, 8'u8),
  (0x7ffc'u32, 15'u8), (0x20'u32, 6'u8),
  (0xffb'u32, 12'u8), (0x3fc'u32, 10'u8),
  (0x1ffa'u32, 13'u8), (0x21'u32, 6'u8),
  (0x5d'u32, 7'u8), (0x5e'u32, 7'u8),
  (0x5f'u32, 7'u8), (0x60'u32, 7'u8),
  (0x61'u32, 7'u8), (0x62'u32, 7'u8),
  (0x63'u32, 7'u8), (0x64'u32, 7'u8),
  (0x65'u32, 7'u8), (0x66'u32, 7'u8),
  (0x67'u32, 7'u8), (0x68'u32, 7'u8),
  (0x69'u32, 7'u8), (0x6a'u32, 7'u8),
  (0x6b'u32, 7'u8), (0x6c'u32, 7'u8),
  (0x6d'u32, 7'u8), (0x6e'u32, 7'u8),
  (0x6f'u32, 7'u8), (0x70'u32, 7'u8),
  (0x71'u32, 7'u8), (0x72'u32, 7'u8),
  (0xfc'u32, 8'u8), (0x73'u32, 7'u8),
  (0xfd'u32, 8'u8), (0x1ffb'u32, 13'u8),
  (0x7fff0'u32, 19'u8), (0x1ffc'u32, 13'u8),
  (0x3ffc'u32, 14'u8), (0x22'u32, 6'u8),
  (0x7ffd'u32, 15'u8), (0x3'u32, 5'u8),
  (0x23'u32, 6'u8), (0x4'u32, 5'u8),
  (0x24'u32, 6'u8), (0x5'u32, 5'u8),
  (0x25'u32, 6'u8), (0x26'u32, 6'u8),
  (0x27'u32, 6'u8), (0x6'u32, 5'u8),
  (0x74'u32, 7'u8), (0x75'u32, 7'u8),
  (0x28'u32, 6'u8), (0x29'u32, 6'u8),
  (0x2a'u32, 6'u8), (0x7'u32, 5'u8),
  (0x2b'u32, 6'u8), (0x76'u32, 7'u8),
  (0x2c'u32, 6'u8), (0x8'u32, 5'u8),
  (0x9'u32, 5'u8), (0x2d'u32, 6'u8),
  (0x77'u32, 7'u8), (0x78'u32, 7'u8),
  (0x79'u32, 7'u8), (0x7a'u32, 7'u8),
  (0x7b'u32, 7'u8), (0x7ffe'u32, 15'u8),
  (0x7fc'u32, 11'u8), (0x3ffd'u32, 14'u8),
  (0x1ffd'u32, 13'u8), (0xffffffc'u32, 28'u8),
  (0xfffe6'u32, 20'u8), (0x3fffd2'u32, 22'u8),
  (0xfffe7'u32, 20'u8), (0xfffe8'u32, 20'u8),
  (0x3fffd3'u32, 22'u8), (0x3fffd4'u32, 22'u8),
  (0x3fffd5'u32, 22'u8), (0x7fffd9'u32, 23'u8),
  (0x3fffd6'u32, 22'u8), (0x7fffda'u32, 23'u8),
  (0x7fffdb'u32, 23'u8), (0x7fffdc'u32, 23'u8),
  (0x7fffdd'u32, 23'u8), (0x7fffde'u32, 23'u8),
  (0xffffeb'u32, 24'u8), (0x7fffdf'u32, 23'u8),
  (0xffffec'u32, 24'u8), (0xffffed'u32, 24'u8),
  (0x3fffd7'u32, 22'u8), (0x7fffe0'u32, 23'u8),
  (0xffffee'u32, 24'u8), (0x7fffe1'u32, 23'u8),
  (0x7fffe2'u32, 23'u8), (0x7fffe3'u32, 23'u8),
  (0x7fffe4'u32, 23'u8), (0x1fffdc'u32, 21'u8),
  (0x3fffd8'u32, 22'u8), (0x7fffe5'u32, 23'u8),
  (0x3fffd9'u32, 22'u8), (0x7fffe6'u32, 23'u8),
  (0x7fffe7'u32, 23'u8), (0xffffef'u32, 24'u8),
  (0x3fffda'u32, 22'u8), (0x1fffdd'u32, 21'u8),
  (0xfffe9'u32, 20'u8), (0x3fffdb'u32, 22'u8),
  (0x3fffdc'u32, 22'u8), (0x7fffe8'u32, 23'u8),
  (0x7fffe9'u32, 23'u8), (0x1fffde'u32, 21'u8),
  (0x7fffea'u32, 23'u8), (0x3fffdd'u32, 22'u8),
  (0x3fffde'u32, 22'u8), (0xfffff0'u32, 24'u8),
  (0x1fffdf'u32, 21'u8), (0x3fffdf'u32, 22'u8),
  (0x7fffeb'u32, 23'u8), (0x7fffec'u32, 23'u8),
  (0x1fffe0'u32, 21'u8), (0x1fffe1'u32, 21'u8),
  (0x3fffe0'u32, 22'u8), (0x1fffe2'u32, 21'u8),
  (0x7fffed'u32, 23'u8), (0x3fffe1'u32, 22'u8),
  (0x7fffee'u32, 23'u8), (0x7fffef'u32, 23'u8),
  (0xfffea'u32, 20'u8), (0x3fffe2'u32, 22'u8),
  (0x3fffe3'u32, 22'u8), (0x3fffe4'u32, 22'u8),
  (0x7ffff0'u32, 23'u8), (0x3fffe5'u32, 22'u8),
  (0x3fffe6'u32, 22'u8), (0x7ffff1'u32, 23'u8),
  (0x3ffffe0'u32, 26'u8), (0x3ffffe1'u32, 26'u8),
  (0xfffeb'u32, 20'u8), (0x7fff1'u32, 19'u8),
  (0x3fffe7'u32, 22'u8), (0x7ffff2'u32, 23'u8),
  (0x3fffe8'u32, 22'u8), (0x1ffffec'u32, 25'u8),
  (0x3ffffe2'u32, 26'u8), (0x3ffffe3'u32, 26'u8),
  (0x3ffffe4'u32, 26'u8), (0x7ffffde'u32, 27'u8),
  (0x7ffffdf'u32, 27'u8), (0x3ffffe5'u32, 26'u8),
  (0xfffff1'u32, 24'u8), (0x1ffffed'u32, 25'u8),
  (0x7fff2'u32, 19'u8), (0x1fffe3'u32, 21'u8),
  (0x3ffffe6'u32, 26'u8), (0x7ffffe0'u32, 27'u8),
  (0x7ffffe1'u32, 27'u8), (0x3ffffe7'u32, 26'u8),
  (0x7ffffe2'u32, 27'u8), (0xfffff2'u32, 24'u8),
  (0x1fffe4'u32, 21'u8), (0x1fffe5'u32, 21'u8),
  (0x3ffffe8'u32, 26'u8), (0x3ffffe9'u32, 26'u8),
  (0xffffffd'u32, 28'u8), (0x7ffffe3'u32, 27'u8),
  (0x7ffffe4'u32, 27'u8), (0x7ffffe5'u32, 27'u8),
  (0xfffec'u32, 20'u8), (0xfffff3'u32, 24'u8),
  (0xfffed'u32, 20'u8), (0x1fffe6'u32, 21'u8),
  (0x3fffe9'u32, 22'u8), (0x1fffe7'u32, 21'u8),
  (0x1fffe8'u32, 21'u8), (0x7ffff3'u32, 23'u8),
  (0x3fffea'u32, 22'u8), (0x3fffeb'u32, 22'u8),
  (0x1ffffee'u32, 25'u8), (0x1ffffef'u32, 25'u8),
  (0xfffff4'u32, 24'u8), (0xfffff5'u32, 24'u8),
  (0x3ffffea'u32, 26'u8), (0x7ffff4'u32, 23'u8),
  (0x3ffffeb'u32, 26'u8), (0x7ffffe6'u32, 27'u8),
  (0x3ffffec'u32, 26'u8), (0x3ffffed'u32, 26'u8),
  (0x7ffffe7'u32, 27'u8), (0x7ffffe8'u32, 27'u8),
  (0x7ffffe9'u32, 27'u8), (0x7ffffea'u32, 27'u8),
  (0x7ffffeb'u32, 27'u8), (0xffffffe'u32, 28'u8),
  (0x7ffffec'u32, 27'u8), (0x7ffffed'u32, 27'u8),
  (0x7ffffee'u32, 27'u8), (0x7ffffef'u32, 27'u8),
  (0x7fffff0'u32, 27'u8), (0x3ffffee'u32, 26'u8),
  (0x3fffffff'u32, 30'u8),
]

type HuffNode = object
  child: array[2, int]
  sym: int  # -1 = internal node, else 0..256

var huffNodes {.global.}: seq[HuffNode]
var huffBuilt {.global.}: bool

proc buildHuffman() =
  huffNodes = @[HuffNode(child: [-1, -1], sym: -1)]
  for sym in 0 .. 256:
    let (code, bits) = huffmanCodes[sym]
    var node = 0
    for i in countdown(int(bits) - 1, 0):
      let bit = int((code shr uint32(i)) and 1)
      if huffNodes[node].child[bit] < 0:
        huffNodes[node].child[bit] = huffNodes.len
        huffNodes.add(HuffNode(child: [-1, -1], sym: -1))
      node = huffNodes[node].child[bit]
    huffNodes[node].sym = sym

proc huffmanEncode*(s: string): seq[byte] =
  ## Huffman-encode raw octets, padding with ones (MSB of EOS) to the octet
  ## boundary per RFC 7541 §5.2.
  var acc: uint64 = 0
  var nbits = 0
  result = @[]
  for ch in s:
    let (code, bits) = huffmanCodes[uint8(ch)]
    acc = (acc shl bits) or uint64(code)
    nbits += int(bits)
    while nbits >= 8:
      nbits -= 8
      result.add(byte((acc shr nbits) and 0xFF))
  if nbits > 0:
    # Pad with ones (most significant bits of EOS).
    acc = (acc shl (8 - nbits)) or ((1'u64 shl (8 - nbits)) - 1)
    result.add(byte(acc and 0xFF))

proc huffmanDecode*(data: openArray[byte]): string =
  ## Decode a Huffman string. An EOS code, padding longer than 7 bits, or
  ## non-ones padding raises `HpackError`.
  if not huffBuilt:
    buildHuffman()
    huffBuilt = true
  result = ""
  var node = 0
  var pending = 0      # bits walked since the last emitted symbol
  var pendingOnes = 0  # of those, trailing ones (padding must be all ones)
  for b in data:
    for i in countdown(7, 0):
      let bit = (int(b) shr i) and 1
      node = huffNodes[node].child[bit]
      if node < 0:
        raise hpackError("hpack: invalid Huffman code")
      inc pending
      pendingOnes = if bit == 1: pendingOnes + 1 else: 0
      if huffNodes[node].sym >= 0:
        let sym = huffNodes[node].sym
        if sym == 256:
          raise hpackError("hpack: EOS in Huffman string")
        result.add(char(sym))
        if result.len > HpackMaxStringLen:
          raise hpackError("hpack: string literal too large")
        node = 0
        pending = 0
        pendingOnes = 0
  if node != 0:
    # Incomplete code at the end is padding: at most 7 bits, all ones.
    if pending > 7:
      raise hpackError("hpack: Huffman padding longer than 7 bits")
    if pendingOnes != pending:
      raise hpackError("hpack: bad Huffman padding")

# ── Integer codec (RFC 7541 §5.1) ─────────────────────────────────────

proc encodeInt*(value: int, prefixBits: int, prefixMask: uint8): seq[byte] =
  ## Encode `value` with an N-bit prefix, OR-ing `prefixMask` (the upper
  ## pattern bits) into the first octet.
  assert prefixBits >= 1 and prefixBits <= 8
  let maxPrefix = (1 shl prefixBits) - 1
  result = @[]
  if value < maxPrefix:
    result.add(prefixMask or uint8(value))
    return
  result.add(prefixMask or uint8(maxPrefix))
  var v = value - maxPrefix
  while v >= 128:
    result.add(uint8((v mod 128) + 128))
    v = v div 128
  result.add(uint8(v))

proc decodeInt*(data: openArray[byte], pos: int,
                prefixBits: int): tuple[value: int, next: int] =
  if pos >= data.len:
    raise hpackError("hpack: truncated integer")
  let maxPrefix = (1 shl prefixBits) - 1
  var value = int(data[pos]) and maxPrefix
  var p = pos + 1
  if value < maxPrefix:
    return (value, p)
  var m = 0
  var iter = 0
  while true:
    if p >= data.len:
      raise hpackError("hpack: truncated integer")
    if iter >= 5:
      raise hpackError("hpack: integer representation too long")
    let b = int(data[p])
    inc p
    inc iter
    # Guard against overflow: 5 continuation bytes already cover 32 bits.
    if m < 31:
      value += (b and 127) shl m
    elif (b and 127) != 0:
      raise hpackError("hpack: integer too large")
    m += 7
    if (b and 128) == 0:
      break
  (value, p)

proc encodeString*(s: string, useHuffman = true): seq[byte] =
  let huffed = huffmanEncode(s)
  if useHuffman and huffed.len < s.len:
    result = encodeInt(huffed.len, 7, 0x80'u8)
    for b in huffed: result.add(b)
  else:
    result = encodeInt(s.len, 7, 0x00'u8)
    for c in s: result.add(byte(c))

proc decodeString*(data: openArray[byte],
                   pos: int): tuple[s: string, next: int] =
  if pos >= data.len:
    raise hpackError("hpack: truncated string literal")
  let huff = (data[pos] and 0x80) != 0
  let (length, p) = decodeInt(data, pos, 7)
  if length > HpackMaxStringLen:
    raise hpackError("hpack: string literal too large")
  if p + length > data.len:
    raise hpackError("hpack: truncated string literal")
  var raw = newString(length)
  for i in 0 ..< length:
    raw[i] = char(data[p + i])
  if huff:
    var huffBytes = newSeq[byte](length)
    for i in 0 ..< length:
      huffBytes[i] = data[p + i]
    (huffmanDecode(huffBytes), p + length)
  else:
    (raw, p + length)

# ── Dynamic table ─────────────────────────────────────────────────────

proc newHpackContext*(maxTableSize = HpackDefaultTableSize,
                      maxAllowedSize = HpackDefaultTableSize): HpackContext =
  HpackContext(table: @[], tableSize: 0, maxTableSize: maxTableSize,
               maxAllowedSize: maxAllowedSize,
               lastSignaledSize: maxTableSize)

proc entrySize(name, value: string): int {.inline.} =
  name.len + value.len + 32

proc evictToFit(ctx: var HpackContext) =
  while ctx.table.len > 0 and ctx.tableSize > ctx.maxTableSize:
    let last = ctx.table[^1]
    ctx.tableSize -= entrySize(last.name, last.value)
    ctx.table.setLen(ctx.table.len - 1)

proc setMaxTableSize*(ctx: var HpackContext, size: int) =
  ## Lower (or restore) the table ceiling; evicts immediately. The new
  ## ceiling is announced with a size update at the next `encode`.
  if size > ctx.maxAllowedSize:
    raise hpackError("hpack: table size exceeds protocol limit")
  ctx.maxTableSize = size
  ctx.evictToFit()

proc insertEntry(ctx: var HpackContext, name, value: string) =
  let size = entrySize(name, value)
  if size > ctx.maxTableSize:
    # Entry larger than the table: drain the table, insert nothing (§4.4).
    ctx.table.setLen(0)
    ctx.tableSize = 0
    return
  while ctx.table.len > 0 and ctx.tableSize + size > ctx.maxTableSize:
    let last = ctx.table[^1]
    ctx.tableSize -= entrySize(last.name, last.value)
    ctx.table.setLen(ctx.table.len - 1)
  ctx.table.insert(HpackHeader(name: name, value: value), 0)
  ctx.tableSize += size

proc lookupIndex(ctx: HpackContext, idx: int): HpackHeader =
  if idx < 1:
    raise hpackError("hpack: index 0 is reserved")
  if idx <= HpackStaticTableLen:
    let e = hpackStaticTable[idx - 1]
    return HpackHeader(name: e.name, value: e.value)
  let dyn = idx - HpackStaticTableLen - 1
  if dyn >= ctx.table.len:
    raise hpackError("hpack: index beyond table")
  ctx.table[dyn]

proc lookupName(ctx: HpackContext, idx: int): string =
  ctx.lookupIndex(idx).name

# ── Header block decode (§3, §6) ───────────────────────────────────────

proc decode*(ctx: var HpackContext,
             data: openArray[byte]): seq[HpackHeader] =
  ## Decode one header block, updating the dynamic table. Raises
  ## `HpackError` on any malformed representation.
  result = @[]
  var p = 0
  while p < data.len:
    let b = data[p]
    if (b and 0x80) != 0:
      # Indexed header field (§6.1).
      let (idx, np) = decodeInt(data, p, 7)
      p = np
      result.add(ctx.lookupIndex(idx))
    elif (b and 0xC0) == 0x40:
      # Literal with incremental indexing (§6.2.1).
      let (idx, np) = decodeInt(data, p, 6)
      p = np
      var name: string
      if idx == 0:
        let (n, np2) = decodeString(data, p)
        name = n
        p = np2
      else:
        name = ctx.lookupName(idx)
      let (value, np3) = decodeString(data, p)
      p = np3
      result.add(HpackHeader(name: name, value: value))
      ctx.insertEntry(name, value)
    elif (b and 0xF0) == 0x00 or (b and 0xF0) == 0x10:
      # Literal without indexing (§6.2.2) / never indexed (§6.2.3).
      let never = (b and 0xF0) == 0x10
      let (idx, np) = decodeInt(data, p, 4)
      p = np
      var name: string
      if idx == 0:
        let (n, np2) = decodeString(data, p)
        name = n
        p = np2
      else:
        name = ctx.lookupName(idx)
      let (value, np3) = decodeString(data, p)
      p = np3
      result.add(HpackHeader(name: name, value: value,
                             neverIndexed: never))
    elif (b and 0xE0) == 0x20:
      # Dynamic table size update (§6.3).
      let (newSize, np) = decodeInt(data, p, 5)
      p = np
      if newSize > ctx.maxAllowedSize:
        raise hpackError("hpack: table size update exceeds limit")
      ctx.maxTableSize = newSize
      ctx.evictToFit()
    else:
      raise hpackError("hpack: bad header representation")

# ── Header block encode ───────────────────────────────────────────────

proc findFullMatch(ctx: HpackContext, name, value: string): int =
  ## Combined index (static preferred) or 0.
  for i in 0 ..< HpackStaticTableLen:
    if hpackStaticTable[i].name == name and
       hpackStaticTable[i].value == value:
      return i + 1
  for i, e in ctx.table:
    if e.name == name and e.value == value:
      return HpackStaticTableLen + 1 + i
  0

proc findNameMatch(ctx: HpackContext, name: string): int =
  for i in 0 ..< HpackStaticTableLen:
    if hpackStaticTable[i].name == name:
      return i + 1
  for i, e in ctx.table:
    if e.name == name:
      return HpackStaticTableLen + 1 + i
  0

proc encode*(ctx: var HpackContext, headers: openArray[HpackHeader],
             useHuffman = true): seq[byte] =
  ## Encode a header list. Full matches become indexed fields; everything
  ## else uses incremental indexing (or never-indexed when flagged), with
  ## indexed names where possible. Announces a pending table-size change
  ## first per §4.2.
  result = @[]
  if ctx.maxTableSize != ctx.lastSignaledSize:
    for b in encodeInt(ctx.maxTableSize, 5, 0x20'u8):
      result.add(b)
    ctx.lastSignaledSize = ctx.maxTableSize
  for h in headers:
    let full = ctx.findFullMatch(h.name, h.value)
    if full > 0 and not h.neverIndexed:
      for b in encodeInt(full, 7, 0x80'u8):
        result.add(b)
      continue
    let nameIdx = ctx.findNameMatch(h.name)
    if h.neverIndexed:
      if nameIdx > 0:
        for b in encodeInt(nameIdx, 4, 0x10'u8):
          result.add(b)
      else:
        for b in encodeInt(0, 4, 0x10'u8):
          result.add(b)
        for b in encodeString(h.name, useHuffman):
          result.add(b)
      for b in encodeString(h.value, useHuffman):
        result.add(b)
    else:
      if nameIdx > 0:
        for b in encodeInt(nameIdx, 6, 0x40'u8):
          result.add(b)
      else:
        for b in encodeInt(0, 6, 0x40'u8):
          result.add(b)
        for b in encodeString(h.name, useHuffman):
          result.add(b)
      for b in encodeString(h.value, useHuffman):
        result.add(b)
      ctx.insertEntry(h.name, h.value)
