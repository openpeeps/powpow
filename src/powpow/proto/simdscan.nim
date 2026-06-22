# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## SIMD-accelerated byte scanning for HTTP parsing.
##
## Uses SSE2 (x86) or scalar fallbacks for CRLF detection.
## The key trick: left-shifting the `\n` mask by 1 byte aligns it with `\r`,
## allowing us to detect `\r\n` pairs in a single SIMD pass.

import std/bitops

when defined(amd64) or defined(i386):
  import nimsimd/sse2
  const hasSse2* = true
else:
  const hasSse2* = false

# ── Constants ─────────────────────────────────────────────────────────────────
const
  MaxRequestLine* = 8192  ## Max request line size (must match http.nim)

# ── Scalar fallbacks ─────────────────────────────────────────────────────────

func findCRLFScalar*(buf: ptr UncheckedArray[byte], start, limit: int): int {.inline.} =
  ## Find \r\n starting from `start`. Returns index of \r, or -1 if not found.
  var i = start
  while i < limit:
    if char(buf[i]) == '\r' and char(buf[i + 1]) == '\n':
      return i
    inc i
  return -1

func findDoubleCRLFScalar*(buf: ptr UncheckedArray[byte], start, limit: int): int {.inline.} =
  ## Find \r\n\r\n starting from `start`. Returns index past the final \n, or -1.
  var i = start
  while i <= limit:
    if char(buf[i]) == '\r' and char(buf[i+1]) == '\n' and
       char(buf[i+2]) == '\r' and char(buf[i+3]) == '\n':
      return i + 4  # past the \r\n\r\n
    inc i
  return -1

# ── SSE2 paths (16 bytes / cycle) ────────────────────────────────────────────

when hasSse2:
  func findCRLFSse2*(buf: ptr UncheckedArray[byte], start, limit: int): int =
    ## SSE2-accelerated \r\n scanner.
    let crVec = mm_set1_epi8(cast[int8](0x0D))  # \r
    let lfVec = mm_set1_epi8(cast[int8](0x0A))  # \n
    var i = start

    while i + 16 <= limit:
      let chunk = mm_loadu_si128(cast[ptr M128i](unsafeAddr buf[i]))
      let crMask = mm_cmpeq_epi8(chunk, crVec)      # 0xFF at \r positions
      let lfMask = mm_cmpeq_epi8(chunk, lfVec)      # 0xFF at \n positions
      let lfShifted = mm_srli_si128(lfMask, 1)
      let combined = mm_and_si128(crMask, lfShifted)
      let mask = cast[uint16](mm_movemask_epi8(combined))
      if mask != 0:
        return i + countTrailingZeroBits(mask)
      i += 16

    let scStart = if i > start: i - 1 else: i
    findCRLFScalar(buf, scStart, limit)

  func findDoubleCRLFSse2*(buf: ptr UncheckedArray[byte], start, maxLen: int): int =
    ## SSE2-accelerated \r\n\r\n scanner.
    ##
    ## Uses the same shift trick as findCRLFSse2, but applied twice:
    ## 1. Find \r\n positions (crlfMask = crMask & lfShifted)
    ## 2. Find \r\n\r\n positions (crlfMask & crlfShifted-by-2)
    ##
    ## This is a single SIMD pass, O(n/16), vs the old sliding-window approach.
    let limit = maxLen - 3
    let crVec = mm_set1_epi8(cast[int8](0x0D))
    let lfVec = mm_set1_epi8(cast[int8](0x0A))
    var i = start
    while i + 16 <= limit:
      let chunk = mm_loadu_si128(cast[ptr M128i](unsafeAddr buf[i]))
      let crMask = mm_cmpeq_epi8(chunk, crVec)
      let lfMask = mm_cmpeq_epi8(chunk, lfVec)
      let lfShifted = mm_srli_si128(lfMask, 1)
      let crlfMask = mm_and_si128(crMask, lfShifted)
      let crlfShifted = mm_srli_si128(crlfMask, 2)
      let doubleMask = mm_and_si128(crlfMask, crlfShifted)
      let mask = cast[uint16](mm_movemask_epi8(doubleMask))
      if mask != 0:
        return i + countTrailingZeroBits(mask) + 4
      i += 16
    let scStart = if i > start: i - 3 else: i
    findDoubleCRLFScalar(buf, scStart, limit)

# ── Unified dispatch ─────────────────────────────────────────────────────────

func findCRLF*(buf: ptr UncheckedArray[byte], start, maxLen: int): int {.inline.} =
  ## Find \r\n starting from `start`. Returns index of \r, or -1 if not found.
  if maxLen - start < 2:
    return -1  # Not enough data for CRLF
  let limit = min(maxLen - 1, start + MaxRequestLine)
  when hasSse2: findCRLFSse2(buf, start, limit)
  else:         findCRLFScalar(buf, start, limit)

func findDoubleCRLF*(buf: ptr UncheckedArray[byte], start, maxLen: int): int {.inline.} =
  ## Find \r\n\r\n starting from `start`. Returns index past the final \n, or -1.
  when hasSse2: findDoubleCRLFSse2(buf, start, maxLen)
  else:
    let limit = maxLen - 3
    findDoubleCRLFScalar(buf, start, limit)
