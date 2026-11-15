## A3: opt-in gzip response compression.
import std/[unittest, tables, strutils, os]
import ../src/powpow
import ../src/powpow/proto/httpserver
import pkg/archive/gzipf

const BigText = "compressible payload line. ".repeat(200) # ~5400 B

type Resp = object
  status: int
  headers: Table[string, string]
  body: string

proc parseResp(raw: string): Resp =
  let hEnd = raw.find("\r\n\r\n")
  check hEnd > 0
  let head = raw[0 ..< hEnd]
  let lines = head.split("\r\n")
  result.status = parseInt(lines[0].split(' ')[1])
  for i in 1 ..< lines.len:
    let c = lines[i].find(':')
    if c > 0:
      result.headers[lines[i][0 ..< c].strip().toLowerAscii()] =
        lines[i][c + 1 .. ^1].strip()
  result.body = raw[hEnd + 4 .. ^1]

proc decodeChunked(raw: string): string =
  var pos = 0
  while true:
    let eol = raw.find("\r\n", pos)
    check eol > pos
    let size = fromHex[int](raw[pos ..< eol].strip())
    pos = eol + 2
    if size == 0:
      break
    result.add(raw[pos ..< pos + size])
    pos += size + 2

proc getRaw(port: int, req: string): string =
  ## One request with `Connection: close`; returns the full raw response.
  let loop = newLoop()
  let server = newHttpServer(loop)
  server.compressEnabled = true
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    let p = req.getPath()
    if p == "/big":
      discard res.header("Content-Type", "text/plain")
      res.send(BigText)
    elif p == "/forced":
      discard res.header("Content-Type", "text/plain")
      res.compress(BigText)
    elif p == "/notype":
      res.send(BigText)
    elif p == "/img":
      discard res.header("Content-Type", "image/png")
      res.send(BigText)
    elif p == "/vary":
      discard res.header("Content-Type", "text/plain")
      discard res.header("Vary", "Cookie")
      res.send(BigText)
    elif p == "/file":
      res.sendFile("/tmp/pp_compress_test.txt", req)
  server.listen("127.0.0.1", port)
  var received = ""
  loop.connect("127.0.0.1", port,
    onConnect = proc(conn: Connection) =
      discard conn.send(req),
    onData = proc(conn: Connection, data: openArray[byte]) =
      {.gcsafe.}:
        for b in data:
          received.add(char(b)),
    onClose = proc(conn: Connection) =
      {.gcsafe.}:
        loop.stop()
  )
  discard loop.addTimer(8000) do (id: int):
    server.close()
    loop.stop()
  loop.run()
  loop.close()
  received

proc gunzip(s: string): string =
  gzipDecompress(s)

# ── Unit: Accept-Encoding parsing ────────────────────────────────────────────

test "accepts_gzip_matrix":
  check parseAcceptsGzip("gzip")
  check parseAcceptsGzip("gzip, deflate")
  check parseAcceptsGzip("br, gzip;q=0.8")
  check parseAcceptsGzip("GZip")
  check parseAcceptsGzip("  gzip  ; q=1 ")
  check parseAcceptsGzip("*")
  check parseAcceptsGzip("br;q=0.5, *;q=0.1")
  check not parseAcceptsGzip("")
  check not parseAcceptsGzip("deflate, br")
  check not parseAcceptsGzip("gzip;q=0")
  check not parseAcceptsGzip("gzip;q=0.0, *;q=1") # explicit refusal wins
  check not parseAcceptsGzip("*;q=0")

# ── Integration ─────────────────────────────────────────────────────────────

test "off_by_default_is_identity":
  let loop = newLoop()
  let server = newHttpServer(loop)
  # flag left off
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    discard res.header("Content-Type", "text/plain")
    res.send(BigText)
  server.listen("127.0.0.1", 19890)
  var received = ""
  loop.connect("127.0.0.1", 19890,
    onConnect = proc(conn: Connection) =
      discard conn.send("GET / HTTP/1.1\r\nHost: x\r\n" &
        "Accept-Encoding: gzip\r\nConnection: close\r\n\r\n"),
    onData = proc(conn: Connection, data: openArray[byte]) =
      {.gcsafe.}:
        for b in data:
          received.add(char(b)),
    onClose = proc(conn: Connection) =
      {.gcsafe.}:
        loop.stop()
  )
  discard loop.addTimer(8000) do (id: int):
    server.close()
    loop.stop()
  loop.run()
  loop.close()
  let r = parseResp(received)
  check "content-encoding" notin r.headers
  check r.body == BigText

test "gzip_round_trip":
  let raw = getRaw(19891, "GET /big HTTP/1.1\r\nHost: x\r\n" &
    "Accept-Encoding: gzip\r\nConnection: close\r\n\r\n")
  let r = parseResp(raw)
  check r.headers.getOrDefault("content-encoding") == "gzip"
  check "accept-encoding" in r.headers.getOrDefault("vary", "").toLowerAscii()
  check r.headers.getOrDefault("content-length") == $r.body.len
  check gunzip(r.body) == BigText

test "no_offer_is_identity":
  let raw = getRaw(19892, "GET /big HTTP/1.1\r\nHost: x\r\n" &
    "Connection: close\r\n\r\n")
  let r = parseResp(raw)
  check "content-encoding" notin r.headers
  check r.body == BigText

test "refused_gzip_is_identity":
  let raw = getRaw(19893, "GET /big HTTP/1.1\r\nHost: x\r\n" &
    "Accept-Encoding: gzip;q=0\r\nConnection: close\r\n\r\n")
  let r = parseResp(raw)
  check "content-encoding" notin r.headers
  check r.body == BigText

test "small_body_is_identity":
  let loop = newLoop()
  let server = newHttpServer(loop)
  server.compressEnabled = true
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    discard res.header("Content-Type", "text/plain")
    res.send("tiny")
  server.listen("127.0.0.1", 19894)
  var received = ""
  loop.connect("127.0.0.1", 19894,
    onConnect = proc(conn: Connection) =
      discard conn.send("GET / HTTP/1.1\r\nHost: x\r\n" &
        "Accept-Encoding: gzip\r\nConnection: close\r\n\r\n"),
    onData = proc(conn: Connection, data: openArray[byte]) =
      {.gcsafe.}:
        for b in data:
          received.add(char(b)),
    onClose = proc(conn: Connection) =
      {.gcsafe.}:
        loop.stop()
  )
  discard loop.addTimer(8000) do (id: int):
    server.close()
    loop.stop()
  loop.run()
  loop.close()
  let r = parseResp(received)
  check "content-encoding" notin r.headers
  check r.body == "tiny"

test "absent_content_type_skips":
  let raw = getRaw(19895, "GET /notype HTTP/1.1\r\nHost: x\r\n" &
    "Accept-Encoding: gzip\r\nConnection: close\r\n\r\n")
  let r = parseResp(raw)
  check "content-encoding" notin r.headers
  check r.body == BigText

test "incompressible_type_skips":
  let raw = getRaw(19896, "GET /img HTTP/1.1\r\nHost: x\r\n" &
    "Accept-Encoding: gzip\r\nConnection: close\r\n\r\n")
  let r = parseResp(raw)
  check "content-encoding" notin r.headers
  check r.body == BigText

test "incompressible_body_falls_back":
  let loop = newLoop()
  let server = newHttpServer(loop)
  server.compressEnabled = true
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    var rng = 12345
    var rnd = newString(4096)
    for i in 0 ..< rnd.len:
      rng = (rng * 1103515245 + 12345) and 0x7FFFFFFF
      rnd[i] = char((rng shr 16) mod 256) # high bits: effectively random
    discard res.header("Content-Type", "text/plain")
    res.send(rnd)
  server.listen("127.0.0.1", 19897)
  var received = ""
  loop.connect("127.0.0.1", 19897,
    onConnect = proc(conn: Connection) =
      discard conn.send("GET / HTTP/1.1\r\nHost: x\r\n" &
        "Accept-Encoding: gzip\r\nConnection: close\r\n\r\n"),
    onData = proc(conn: Connection, data: openArray[byte]) =
      {.gcsafe.}:
        for b in data:
          received.add(char(b)),
    onClose = proc(conn: Connection) =
      {.gcsafe.}:
        loop.stop()
  )
  discard loop.addTimer(8000) do (id: int):
    server.close()
    loop.stop()
  loop.run()
  loop.close()
  # Contract: either identity (expansion fallback) or valid gzip.
  var rng = 12345
  var want = newString(4096)
  for i in 0 ..< want.len:
    rng = (rng * 1103515245 + 12345) and 0x7FFFFFFF
    want[i] = char((rng shr 16) mod 256)
  let r = parseResp(received)
  if "content-encoding" in r.headers:
    check r.headers["content-encoding"] == "gzip"
    check gunzip(r.body) == want
  else:
    check r.body == want

test "vary_merges":
  let raw = getRaw(19898, "GET /vary HTTP/1.1\r\nHost: x\r\n" &
    "Accept-Encoding: gzip\r\nConnection: close\r\n\r\n")
  let r = parseResp(raw)
  check r.headers.getOrDefault("content-encoding") == "gzip"
  let vary = r.headers.getOrDefault("vary", "")
  check "Cookie" in vary
  check "accept-encoding" in vary.toLowerAscii()
  check gunzip(r.body) == BigText

test "head_skips":
  let raw = getRaw(19899, "HEAD /big HTTP/1.1\r\nHost: x\r\n" &
    "Accept-Encoding: gzip\r\nConnection: close\r\n\r\n")
  let r = parseResp(raw)
  check "content-encoding" notin r.headers

test "compress_forces_when_flag_off":
  let loop = newLoop()
  let server = newHttpServer(loop)
  # flag left off; explicit compress() still attempts
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    discard res.header("Content-Type", "text/plain")
    res.compress(BigText)
  server.listen("127.0.0.1", 19900)
  var received = ""
  loop.connect("127.0.0.1", 19900,
    onConnect = proc(conn: Connection) =
      discard conn.send("GET / HTTP/1.1\r\nHost: x\r\n" &
        "Accept-Encoding: gzip\r\nConnection: close\r\n\r\n"),
    onData = proc(conn: Connection, data: openArray[byte]) =
      {.gcsafe.}:
        for b in data:
          received.add(char(b)),
    onClose = proc(conn: Connection) =
      {.gcsafe.}:
        loop.stop()
  )
  discard loop.addTimer(8000) do (id: int):
    server.close()
    loop.stop()
  loop.run()
  loop.close()
  let r = parseResp(raw = received)
  check r.headers.getOrDefault("content-encoding") == "gzip"
  check gunzip(r.body) == BigText

test "scatter_path_gzip_round_trip":
  # 60 custom headers force the sendv scatter path with skips + extras.
  let loop = newLoop()
  let server = newHttpServer(loop)
  server.compressEnabled = true
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    discard res.header("Content-Type", "text/plain")
    for i in 0 ..< 60:
      discard res.header("X-Hdr-" & $i, "v" & $i)
    discard res.header("Content-Length", "999999")
    res.send(BigText)
  server.listen("127.0.0.1", 19903)
  var received = ""
  loop.connect("127.0.0.1", 19903,
    onConnect = proc(conn: Connection) =
      discard conn.send("GET / HTTP/1.1\r\nHost: x\r\n" &
        "Accept-Encoding: gzip\r\nConnection: close\r\n\r\n"),
    onData = proc(conn: Connection, data: openArray[byte]) =
      {.gcsafe.}:
        for b in data:
          received.add(char(b)),
    onClose = proc(conn: Connection) =
      {.gcsafe.}:
        loop.stop()
  )
  discard loop.addTimer(8000) do (id: int):
    server.close()
    loop.stop()
  loop.run()
  loop.close()
  let r = parseResp(received)
  check r.headers.getOrDefault("content-encoding") == "gzip"
  check r.headers.getOrDefault("content-length") == $r.body.len
  check r.headers.getOrDefault("x-hdr-59") == "v59"
  check gunzip(r.body) == BigText

test "sendfile_gzip_round_trip":
  writeFile("/tmp/pp_compress_test.txt", BigText)
  let raw = getRaw(19901, "GET /file HTTP/1.1\r\nHost: x\r\n" &
    "Accept-Encoding: gzip\r\nConnection: close\r\n\r\n")
  removeFile("/tmp/pp_compress_test.txt")
  let hEnd = raw.find("\r\n\r\n")
  check hEnd > 0
  var headers = initTable[string, string]()
  for line in raw[0 ..< hEnd].split("\r\n")[1 .. ^1]:
    let c = line.find(':')
    if c > 0:
      headers[line[0 ..< c].strip().toLowerAscii()] = line[c + 1 .. ^1].strip()
  check headers.getOrDefault("content-encoding") == "gzip"
  check "chunked" in headers.getOrDefault("transfer-encoding", "")
  check "content-length" notin headers
  check gunzip(decodeChunked(raw[hEnd + 4 .. ^1])) == BigText

test "sendfile_range_wins_identity":
  writeFile("/tmp/pp_compress_test.txt", BigText)
  let raw = getRaw(19902, "GET /file HTTP/1.1\r\nHost: x\r\n" &
    "Accept-Encoding: gzip\r\nRange: bytes=0-99\r\nConnection: close\r\n\r\n")
  removeFile("/tmp/pp_compress_test.txt")
  let r = parseResp(raw)
  check r.status == 206
  check "content-encoding" notin r.headers
  check r.body == BigText[0 ..< 100]
