## Regression test for Firefox POST with cookie header
## Replicates: POST /auth/register with Firefox's exact headers

import ../src/powpow
import std/[httpcore, strutils]

proc buildFirefoxPost(): string =
  let body = "email=test%40example.com&password=%27r%5DK5h%5DkBt%26%26jD%29&password_confirm=%27r%5DK5h%5DkBt%26%26jD%29"
  let headers = "POST /auth/register HTTP/1.1\r\n" &
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
  headers

when isMainModule:
  echo "Building Firefox POST request..."
  let raw = buildFirefoxPost()
  echo "Total length: ", raw.len, " bytes"
  echo ""
  
  # Parse the request
  let parser = newHttpParser()
  let phase = parser.feed(raw)
  echo "After feed: phase=", phase, " isComplete=", parser.isComplete()
  echo "headerEnd=", parser.headerEnd, " contentLength=", parser.contentLength
  echo "bufLen=", parser.bufLen

  if parser.isComplete():
    let req = parser.getRequest()
    echo "Method: ", req.getMethod()
    echo "Path: ", req.getPath()
    echo "Body: ", req.getBodyString()
    echo "Content-Length: ", req.getContentLength()
    let headers = req.getHeaders()
    echo "Headers:"
    for k, v in headers:
      echo "  ", k, ": ", v
    echo ""
    echo "SUCCESS: Parser completed correctly"
  else:
    echo "FAILURE: Parser did not complete!"
    echo "Phase: ", parser.phase
    echo ""
    # Dump the buffer to see what's there
    echo "Buffer dump (first 300 bytes):"
    var head = newString(min(raw.len, 300))
    copyMem(addr head[0], addr parser.buf[0], head.len)
    echo head
    echo "---"
    echo "Buffer dump (full, as raw bytes with CR/LF markers):"
    for i in 0..<min(raw.len, 850):
      let b = parser.buf[i]
      if b == 13: echo "  [", i, "] = CR"
      elif b == 10: echo "  [", i, "] = LF"
      elif b >= 32 and b < 127: echo "  [", i, "] = '", char(b), "'"
      else: echo "  [", i, "] = ", b
