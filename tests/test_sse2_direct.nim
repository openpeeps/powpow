## Force the SSE2 loop to run by using a buffer large enough
import ../src/powpow/proto/simdscan
import std/[strutils, bitops]

when isMainModule:
  when hasSse2:
    import nimsimd/sse2

    # Create a buffer where the SSE2 loop MUST process a chunk 
    # containing \r\n\r\n. The SSE2 loop processes chunks while i+16 <= maxLen-3.
    # For maxLen=738, limit=735. SSE2 loop: i=0,16,32,...,720 (720+16=736>735, so stops at 704)
    # For maxLen=739, limit=736. SSE2 loop: i=0,16,32,...,720 (720+16=736<=736, processes 720!)
    
    # Build: 720 bytes of garbage + \r\n\r\n at 728 + padding to reach desired length
    var buf = newSeq[byte](739)
    for i in 0..<727:
      buf[i] = 'A'.byte
    buf[727] = 'x'.byte
    buf[728] = 13 # CR
    buf[729] = 10 # LF
    buf[730] = 13 # CR
    buf[731] = 10 # LF
    for i in 732..<739:
      buf[i] = 'B'.byte
    
    echo "Buffer length: ", buf.len
    echo "Bytes 725-735:"
    for i in 725..min(735, buf.len-1):
      let b = buf[i]
      if b == 13: echo "  [", i, "] = CR"
      elif b == 10: echo "  [", i, "] = LF"
      elif b >= 32 and b < 127: echo "  [", i, "] = '", char(b), "'"
      else: echo "  [", i, "] = ", b
    
    # Test with maxLen=739 (SSE2 processes chunk 720-735)
    let r = findDoubleCRLFSse2(cast[ptr UncheckedArray[byte]](addr buf[0]), 0, 739)
    echo "\nresult: ", r, " (expected ", 728+4, ")"

    # Also test the full overlay: place the exact Firefox POST bytes
    # at positions 720-735 and see if SSE2 finds it
    var buf2 = newSeq[byte](739)
    for i in 0..<719:
      buf2[i] = 'A'.byte
    # Place the Firefox chunk at 720-735: "...no-cache\r\n\r\nemai"
    buf2[719] = 'x'.byte  # extra byte to make it 720
    buf2[720] = 'n'.byte  # 720
    buf2[721] = 'o'.byte
    buf2[722] = '-'.byte
    buf2[723] = 'c'.byte
    buf2[724] = 'a'.byte
    buf2[725] = 'c'.byte
    buf2[726] = 'h'.byte
    buf2[727] = 'e'.byte  # 727
    buf2[728] = 13  # CR
    buf2[729] = 10  # LF
    buf2[730] = 13  # CR
    buf2[731] = 10  # LF
    buf2[732] = 'e'.byte
    buf2[733] = 'm'.byte
    buf2[734] = 'a'.byte
    buf2[735] = 'i'.byte
    for i in 736..<739:
      buf2[i] = 'B'.byte
    
    echo "\nTest with exact Firefox chunk at 720-735:"
    let r2 = findDoubleCRLFSse2(cast[ptr UncheckedArray[byte]](addr buf2[0]), 0, 739)
    echo "result: ", r2, " (expected ", 728+4, ")"
