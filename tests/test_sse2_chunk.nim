## Test SSE2 findDoubleCRLF on the exact problematic chunk (bytes 720-735)
import ../src/powpow/proto/simdscan
import std/[strutils, bitops]

when isMainModule:
  when hasSse2:
    import nimsimd/sse2

    # Build the exact chunk from the Firefox POST at positions 720-735
    # These are the bytes that contain \r\n\r\n at positions 728-731
    var chunk = newSeq[byte](16)
    # Bytes 720-727: "e\r\nPragma: no-cache\r\nCache-Control: no-cache\r\n\r\nemail=..."
    # But let's build it exactly from known data:
    # Position 720 in the full buffer = 'n' (from "Cache-Control: no-cache" → "no-cache\r\n\r\n")
    
    # Actually, let me construct the EXACT 16-byte slice at positions 720-735
    # From the byte dump: [720]='n', [721]='o', ...[727]='e', [728]=CR, [729]=LF, [730]=CR, [731]=LF, [732]='e', [733]='m', [734]='a', [735]='i'
    chunk[0] = 'n'.byte  # 720
    chunk[1] = 'o'.byte  # 721
    chunk[2] = '-'.byte  # 722
    chunk[3] = 'c'.byte  # 723
    chunk[4] = 'a'.byte  # 724
    chunk[5] = 'c'.byte  # 725
    chunk[6] = 'h'.byte  # 726
    chunk[7] = 'e'.byte  # 727
    chunk[8] = 13  # CR at 728
    chunk[9] = 10  # LF at 729
    chunk[10] = 13 # CR at 730
    chunk[11] = 10 # LF at 731
    chunk[12] = 'e'.byte # 732
    chunk[13] = 'm'.byte # 733
    chunk[14] = 'a'.byte # 734
    chunk[15] = 'i'.byte # 735
    
    echo "Testing chunk (bytes 720-735):"
    for i in 0..15:
      let b = chunk[i]
      if b == 13: echo "  [", 720+i, "] = CR"
      elif b == 10: echo "  [", 720+i, "] = LF"
      elif b >= 32 and b < 127: echo "  [", 720+i, "] = '", char(b), "'"
      else: echo "  [", 720+i, "] = ", b

    # Test 1: isolate the chunk with maxLen=16
    let r1 = findDoubleCRLFSse2(cast[ptr UncheckedArray[byte]](addr chunk[0]), 0, 16)
    echo "\nTest isolated chunk (maxLen=16): ", r1, " (expected 12)"

    # Test 2: chunk with maxLen=835 (simulating position in full buffer)
    let r2 = findDoubleCRLFSse2(cast[ptr UncheckedArray[byte]](addr chunk[0]), 0, 835)
    echo "Test isolated chunk (maxLen=835): ", r2, " (expected 12)"

    # Test 3: chunk with offset 720 in a larger buffer
    var bigBuf = newSeq[byte](736)
    for i in 0..<720:
      bigBuf[i] = 'x'.byte
    for i in 720..735:
      bigBuf[i] = chunk[i - 720]
    let r3 = findDoubleCRLFSse2(cast[ptr UncheckedArray[byte]](addr bigBuf[0]), 0, bigBuf.len)
    echo "Test bigBuf (736 bytes): ", r3, " (expected 724)"

    # Test 4: Full Firefox buffer - check what happens to SSE2 at each chunk
    echo "\n--- Testing each 16-byte chunk in full Firefox POST ---"
    let body = "email=test%40example.com&password=%27r%5DK5h%5DkBt%26%26jD%29&password_confirm=%27r%5DK5h%5DkBt%26%26jD%29"
    let raw = "POST /auth/register HTTP/1.1\r\n" &
      "Host: 127.0.0.1:8000\r\n" &
      "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:152.0) Gecko/20100101 Firefox/152.0\r\n" &
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" &
      "Accept-Language: en-US,en;q=0.9\r\n" &
      "Accept-Encoding: gzip, deflate, br, zstd\r\n" &
      "Content-Type: application/x-www-form-urlencoded\r\n" &
      "Content-Length: " & $body.len & "\r\n" &
      "Origin: http://127.0.0.1:8000\r\n" &
      "Sec-GPC: 1\r\n" &
      "Connection: keep-alive\r\n" &
      "Referer: http://127.0.0.1:8000/auth/register\r\n" &
      "Cookie: ssid=FHsbnuNO2uBtpSxfEgQ9LI7YV4fC7u0mrItyJk5DAM\r\n" &
      "Upgrade-Insecure-Requests: 1\r\n" &
      "Sec-Fetch-Dest: document\r\n" &
      "Sec-Fetch-Mode: navigate\r\n" &
      "Sec-Fetch-Site: same-origin\r\n" &
      "Sec-Fetch-User: ?1\r\n" &
      "Priority: u=0, i\r\n" &
      "Pragma: no-cache\r\n" &
      "Cache-Control: no-cache\r\n" &
      "\r\n" & body
    var buf = newSeq[byte](raw.len)
    copyMem(addr buf[0], addr raw[0], raw.len)

    # Test each 16-byte chunk starting from 704
    for start in [0, 16, 32, 704, 720, 736, 768, 784, 800, 816]:
      let limit = raw.len - 3
      if start + 16 <= limit:
        let r = findDoubleCRLFSse2(cast[ptr UncheckedArray[byte]](addr buf[start]), start, raw.len)
        echo "  start=", start, " result=", r
