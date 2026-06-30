# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## SIMD-accelerated byte scanning for HTTP parsing.
##
## Uses SSE2 (x86) or scalar fallbacks for CRLF detection.
## The key trick: shifting the `\n` mask by 1 byte aligns it with `\r`,
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

func findCRLFScalar*(buf: ptr UncheckedArray[byte], start, maxLen: int): int {.inline.} =
  ## Find \r\n starting from `start`. Returns index of \r, or -1 if not found.
  ## Safe: only reads bytes 0..maxLen-1.
  var i = start
  while i + 1 < maxLen:
    if char(buf[i]) == '\r' and char(buf[i + 1]) == '\n':
      return i
    inc i
  -1

func findDoubleCRLFScalar*(buf: ptr UncheckedArray[byte], start, maxLen: int): int {.inline.} =
  ## Find \r\n\r\n starting from `start`. Returns index past the final \n, or -1.
  ## Safe: only reads bytes 0..maxLen-1.
  var i = start
  while i + 3 < maxLen:
    if char(buf[i]) == '\r' and char(buf[i+1]) == '\n' and
       char(buf[i+2]) == '\r' and char(buf[i+3]) == '\n':
      return i + 4  # past the \r\n\r\n
    inc i
  -1

# ── SSE2 paths (16 bytes / cycle) ────────────────────────────────────────────

when hasSse2:
  func findCRLFSse2*(buf: ptr UncheckedArray[byte], start, scanLen: int): int {.inline.} =
    ## SSE2-accelerated \r\n scanner. Scans up to scanLen bytes.
    ## Falls back to full scalar scan to catch \r\n straddling two chunks.
    let crVec = mm_set1_epi8(cast[int8](0x0D))
    let lfVec = mm_set1_epi8(cast[int8](0x0A))
    var i = start
    while i + 16 <= scanLen:
      let chunk = mm_loadu_si128(cast[ptr M128i](unsafeAddr buf[i]))
      let crMask = mm_cmpeq_epi8(chunk, crVec)
      let lfMask = mm_cmpeq_epi8(chunk, lfVec)
      let lfShifted = mm_srli_si128(lfMask, 1)
      let combined = mm_and_si128(crMask, lfShifted)
      let mask = cast[uint16](mm_movemask_epi8(combined))
      if mask != 0:
        return i + countTrailingZeroBits(mask)
      i += 16
    # Scalar fallback catches patterns spanning two 16-byte chunks
    findCRLFScalar(buf, start, scanLen)

  func findDoubleCRLFSse2*(buf: ptr UncheckedArray[byte], start, maxLen: int): int {.inline.} =
    ## SSE2-accelerated \r\n\r\n scanner.
    ## Falls back to full scalar scan to catch \r\n\r\n straddling two chunks.
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
    # Scalar fallback catches patterns spanning two 16-byte chunks
    findDoubleCRLFScalar(buf, start, maxLen)

# ── Unified dispatch ─────────────────────────────────────────────────────────

func findCRLF*(buf: ptr UncheckedArray[byte], start, maxLen: int): int {.inline.} =
  ## Find \r\n starting from `start`. Returns index of \r, or -1 if not found.
  ## Scans at most MaxRequestLine bytes.
  if maxLen - start < 2:
    return -1
  let scanLen = min(maxLen, start + MaxRequestLine)
  when hasSse2: findCRLFSse2(buf, start, scanLen)
  else:         findCRLFScalar(buf, start, scanLen)

func findDoubleCRLF*(buf: ptr UncheckedArray[byte], start, maxLen: int): int {.inline.} =
  ## Find \r\n\r\n starting from `start`. Returns index past the final \n, or -1.
  when hasSse2: findDoubleCRLFSse2(buf, start, maxLen)
  else:         findDoubleCRLFScalar(buf, start, maxLen)
