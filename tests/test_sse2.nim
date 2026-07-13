## Direct test of SSE2 findDoubleCRLF
import ../src/powpow/proto/simdscan
import std/[strutils, bitops]

when isMainModule:
  echo "hasSse2 = ", hasSse2
  
  when hasSse2:
    import nimsimd/sse2
    
    # Test 1: Simple \r\n\r\n at position 0
    block:
      var buf = newSeq[byte](16)
      buf[0] = '\r'.byte; buf[1] = '\n'.byte; buf[2] = '\r'.byte; buf[3] = '\n'.byte
      let r = findDoubleCRLFSse2(cast[ptr UncheckedArray[byte]](addr buf[0]), 0, 16)
      echo "Test 1 (simple at pos 0): ", r, " (expected 4)"

    # Test 2: \r\n\r\n at position 8
    block:
      var buf = newSeq[byte](16)
      buf[8] = '\r'.byte; buf[9] = '\n'.byte; buf[10] = '\r'.byte; buf[11] = '\n'.byte
      let r = findDoubleCRLFSse2(cast[ptr UncheckedArray[byte]](addr buf[0]), 0, 16)
      echo "Test 2 (at pos 8): ", r, " (expected 12)"

    # Test 3: Single \r\n at position 8 (should not match)
    block:
      var buf = newSeq[byte](16)
      buf[8] = '\r'.byte; buf[9] = '\n'.byte
      let r = findDoubleCRLFSse2(cast[ptr UncheckedArray[byte]](addr buf[0]), 0, 16)
      echo "Test 3 (single CRLF at 8): ", r, " (expected -1)"

    # Test 4: \r\n\r\n at the very end of limit (pos 12, maxLen=16)
    block:
      var buf = newSeq[byte](16)
      buf[12] = '\r'.byte; buf[13] = '\n'.byte; buf[14] = '\r'.byte; buf[15] = '\n'.byte
      let r = findDoubleCRLFSse2(cast[ptr UncheckedArray[byte]](addr buf[0]), 0, 16)
      echo "Test 4 (at end, maxLen=16): ", r, " (expected 16)"

    # Test 5: \r\n\r\n at pos 8, maxLen=12 (limit=9)
    block:
      var buf = newSeq[byte](12)
      buf[8] = '\r'.byte; buf[9] = '\n'.byte; buf[10] = '\r'.byte; buf[11] = '\n'.byte
      let r = findDoubleCRLFSse2(cast[ptr UncheckedArray[byte]](addr buf[0]), 0, 12)
      echo "Test 5 (at 8, maxLen=12): ", r, " (expected 12)"

    # Test 6: Full Firefox POST buffer
    block:
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
      # Debug: print bytes 725-735
      echo "\nBytes 725-735:"
      for i in 725..min(735, raw.len-1):
        let b = buf[i]
        if b == 13: echo "  [", i, "] = CR (\\r)"
        elif b == 10: echo "  [", i, "] = LF (\\n)"
        elif b >= 32 and b < 127: echo "  [", i, "] = '", char(b), "'"
        else: echo "  [", i, "] = ", b
      let r = findDoubleCRLFSse2(cast[ptr UncheckedArray[byte]](addr buf[0]), 0, raw.len)
      echo "Test 6 (full Firefox POST): ", r, " (expected 732)"
