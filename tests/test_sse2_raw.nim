## Test raw SSE2 intrinsics for \r\n\r\n detection
import std/bitops

when defined(amd64) or defined(i386):
  import nimsimd/sse2

  proc findDoubleCRLF_srli(buf: ptr UncheckedArray[byte], maxLen: int): int {.inline.} =
    ## ORIGINAL code: uses mm_srli_si128 (RIGHT shift)
    let crVec = mm_set1_epi8(cast[int8](0x0D))
    let lfVec = mm_set1_epi8(cast[int8](0x0A))
    let limit = maxLen - 3
    var i = 0
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
    let scStart = if i > 0: i - 3 else: 0
    # scalar fallback
    var j = scStart
    while j <= limit:
      if char(buf[j]) == '\r' and char(buf[j+1]) == '\n' and
         char(buf[j+2]) == '\r' and char(buf[j+3]) == '\n':
        return j + 4
      inc j
    return -1

  proc findDoubleCRLF_slli(buf: ptr UncheckedArray[byte], maxLen: int): int {.inline.} =
    ## FIXED code: uses mm_slli_si128 (LEFT shift)
    let crVec = mm_set1_epi8(cast[int8](0x0D))
    let lfVec = mm_set1_epi8(cast[int8](0x0A))
    let limit = maxLen - 3
    var i = 0
    while i + 16 <= limit:
      let chunk = mm_loadu_si128(cast[ptr M128i](unsafeAddr buf[i]))
      let crMask = mm_cmpeq_epi8(chunk, crVec)
      let lfMask = mm_cmpeq_epi8(chunk, lfVec)
      let lfShifted = mm_slli_si128(lfMask, 1)
      let crlfMask = mm_and_si128(crMask, lfShifted)
      let crlfShifted = mm_slli_si128(crlfMask, 2)
      let doubleMask = mm_and_si128(crlfMask, crlfShifted)
      let mask = cast[uint16](mm_movemask_epi8(doubleMask))
      if mask != 0:
        return i + countTrailingZeroBits(mask) + 4
      i += 16
    let scStart = if i > 0: i - 3 else: 0
    # scalar fallback
    var j = scStart
    while j <= limit:
      if char(buf[j]) == '\r' and char(buf[j+1]) == '\n' and
         char(buf[j+2]) == '\r' and char(buf[j+3]) == '\n':
        return j + 4
      inc j
    return -1

  when isMainModule:
    # Build a 16-byte chunk: ABC\r\n\r\nDEFGHIJK
    var chunk16 = newSeq[byte](16)
    for i in 0..2: chunk16[i] = byte(ord('A') + i)
    chunk16[3] = 13  # \r
    chunk16[4] = 10  # \n
    chunk16[5] = 13  # \r
    chunk16[6] = 10  # \n
    for i in 7..15: chunk16[i] = byte(ord('D') + i - 7)
    
    echo "16-byte chunk:"
    for i in 0..15:
      let b = chunk16[i]
      if b == 13: echo "  [", i, "] = CR"
      elif b == 10: echo "  [", i, "] = LF"
      else: echo "  [", i, "] = '", char(b), "'"
    
    let ptr16 = cast[ptr UncheckedArray[byte]](addr chunk16[0])
    
    # Test scalar: should find at position 3, return 7
    var j = 0
    let limit16 = 13
    var found = -1
    while j <= limit16:
      if char(ptr16[j]) == '\r' and char(ptr16[j+1]) == '\n' and
         char(ptr16[j+2]) == '\r' and char(ptr16[j+3]) == '\n':
        found = j + 4
        break
      inc j
    echo "\nScalar on isolated chunk: ", found, " (expected 7)"
    
    # Test full 16-byte chunk with SRLI and SLLI
    let r1 = findDoubleCRLF_srli(ptr16, 16)
    echo "SRLI (original) on isolated chunk: ", r1, " (expected 7)"
    
    let r2 = findDoubleCRLF_slli(ptr16, 16)
    echo "SLLI (fixed) on isolated chunk: ", r2, " (expected 7)"
    
    # Now embed the chunk in a > 32 byte buffer to force SSE2 loop
    # Need maxLen > 35 so that limit > 32 and SSE2 processes at least 2 chunks
    var bigBuf = newSeq[byte](36)
    for i in 0..<20: bigBuf[i] = 'X'.byte
    for i in 20..35: bigBuf[i] = chunk16[i-20]
    
    let ptrBig = cast[ptr UncheckedArray[byte]](addr bigBuf[0])
    
    # \r\n\r\n in bigBuf is at position 20+3=23, should return 27
    echo "\nBig buf (36 bytes):"
    echo "  MaxLen=36, limit=33"
    echo "  SSE2 loop: i=0 (0+16<=33),", " i=16 (16+16<=33),", " i=32 (32+16>33, stop)"
    echo "  \r\n\r\n at position 23, chunk at i=16 covers bytes 16-31"
    
    let r3 = findDoubleCRLF_srli(ptrBig, 36)
    echo "  SRLI (original): ", r3, " (expected 27)"
    
    let r4 = findDoubleCRLF_slli(ptrBig, 36)
    echo "  SLLI (fixed): ", r4, " (expected 27)"
    
    # Test each SSE2 chunk: manually 
    echo "\n--- Manual SSE2 chunk tests ---"
    for chunkStart in [0, 16]:
      let chunkMM = mm_loadu_si128(cast[ptr M128i](unsafeAddr bigBuf[chunkStart]))
      let crMask = mm_cmpeq_epi8(chunkMM, mm_set1_epi8(cast[int8](0x0D)))
      let lfMask = mm_cmpeq_epi8(chunkMM, mm_set1_epi8(cast[int8](0x0A)))
      let lfSrli = mm_srli_si128(lfMask, 1)
      let crlfSrli = mm_and_si128(crMask, lfSrli)
      let crlfSrliShifted = mm_srli_si128(crlfSrli, 2)
      let doubleSrli = mm_and_si128(crlfSrli, crlfSrliShifted)
      let maskSrli = cast[uint16](mm_movemask_epi8(doubleSrli))
      let lfSlli = mm_slli_si128(lfMask, 1)
      let crlfSlli = mm_and_si128(crMask, lfSlli)
      let crlfSlliShifted = mm_slli_si128(crlfSlli, 2)
      let doubleSlli = mm_and_si128(crlfSlli, crlfSlliShifted)
      let maskSlli = cast[uint16](mm_movemask_epi8(doubleSlli))
      echo "  Chunk ", chunkStart, ": SRLI mask=", maskSrli, " SLLI mask=", maskSlli
