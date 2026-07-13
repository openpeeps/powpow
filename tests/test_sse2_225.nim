## Test SSE2 with exact curl POST buffer (225 bytes)
import ../src/powpow/proto/simdscan
import std/[bitops, strutils]

when isMainModule:
  when hasSse2:
    import nimsimd/sse2

  # Build a 225 byte buffer with \r\n\r\n at position 164
  var buf = newSeq[byte](225)
  var pos = 0
  template add(s: string) =
    for c in s:
      buf[pos] = c.byte; inc pos
  add("POST /auth/register HTTP/1.1\r\n")
  add("Host: 127.0.0.1:8000\r\n")
  add("User-Agent: curl/8.20.0\r\n")
  add("Accept: */*\r\n")
  add("Content-Length: 76\r\n")
  add("Content-Type: application/x-www-form-urlencoded\r\n")
  add("\r\n")
  # Pad the body to fill up to 225 bytes
  while pos < 225:
    buf[pos] = 'x'.byte; inc pos

  echo "Buffer length: ", buf.len
  if buf.len > 166:
    echo "Bytes 164-169:"
    for i in 164..min(169, buf.len-1):
      let b = buf[i]
      if b == 13: echo "  [", i, "] = CR"
      elif b == 10: echo "  [", i, "] = LF"
      elif b >= 32 and b < 127: echo "  [", i, "] = '", char(b), "'"
      else: echo "  [", i, "] = ", b
  
  let ptrBuf = cast[ptr UncheckedArray[byte]](addr buf[0])
  
  echo "\nHasSse2: ", hasSse2
  let r = findDoubleCRLF(ptrBuf, 0, buf.len)
  echo "findDoubleCRLF: ", r, " (expected ", 168, ")"
  
  # Manual scalar check
  var found = -1
  let limit = buf.len - 3
  for i in 0..limit:
    if buf[i] == 13 and buf[i+1] == 10 and buf[i+2] == 13 and buf[i+3] == 10:
      found = i + 4
      echo "Scalar found at i=", i, " result=", i+4
      break
  echo "Scalar result: ", found