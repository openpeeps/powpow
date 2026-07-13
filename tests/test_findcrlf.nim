## Direct test of findDoubleCRLF
import ../src/powpow/proto/simdscan
import std/strutils

when isMainModule:
  # Build the exact Firefox POST request
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

  echo "Total length: ", raw.len

  # Test findDoubleCRLF directly
  var buf = newSeq[byte](raw.len)
  copyMem(addr buf[0], addr raw[0], raw.len)
  echo "hasSse2=", hasSse2
  let result = findDoubleCRLF(cast[ptr UncheckedArray[byte]](addr buf[0]), 0, raw.len)
  echo "findDoubleCRLF result: ", result

  # Manual check at position 728
  if raw.len > 732:
    echo "Bytes 728-731:"
    echo "  [728] = ", buf[728], " (char='", char(buf[728]), "')"
    echo "  [729] = ", buf[729], " (char='", char(buf[729]), "')"
    echo "  [730] = ", buf[730], " (char='", char(buf[730]), "')"
    echo "  [731] = ", buf[731], " (char='", char(buf[731]), "')"
    echo "Match: ", buf[728] == 13 and buf[729] == 10 and buf[730] == 13 and buf[731] == 10

  # Manual scan at position 728
  echo ""
  echo "Manual scan around position 728:"
  let start = 720
  let limit = raw.len - 3
  for i in start..<min(start+20, limit):
    if i+3 < raw.len:
      let match = buf[i] == '\r'.byte and buf[i+1] == '\n'.byte and buf[i+2] == '\r'.byte and buf[i+3] == '\n'.byte
      if match:
        echo "  found at i=", i, " (return ", i+4, ")"
    else:
      echo "  i=", i, " out of bounds (buf.len=", buf.len, ")"
