## A4: haproxy PROXY v1/v2 ingress.
import std/[unittest, strutils]
import ../src/powpow
import ../src/powpow/proto/httpserver
import ../src/powpow/proto/http

proc toBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i in 0 ..< s.len:
    result[i] = byte(s[i])

# ── Unit: header parsing ─────────────────────────────────────────────────────

test "proxy_header_matrix":
  template pr(s: string): auto =
    parseProxyHeader(toBytes(s))
  # valid v1
  var r = pr("PROXY TCP4 192.168.1.10 10.0.0.1 12345 80\r\nGET / HTTP/1.1\r\n")
  check r.status == proxyOk
  check r.consumed == 43
  check r.srcIp == "192.168.1.10"
  r = pr("PROXY TCP6 2001:db8::1 2001:db8::2 443 8080\r\n")
  check r.status == proxyOk
  check r.srcIp == "2001:db8::1"
  # UNKNOWN keeps the socket peer
  r = pr("PROXY UNKNOWN\r\nGET / HTTP/1.1\r\n")
  check r.status == proxyIgnored
  check r.consumed == 15
  r = pr("PROXY UNKNOWN some future tokens here\r\n")
  check r.status == proxyIgnored
  # split header
  check pr("PROXY TCP4 1.2.3.4").status == proxyNeedMore
  check pr("PROXY").status == proxyNeedMore
  check pr("").status == proxyNeedMore
  check pr("\r\n\r\n\0\r\nQUIT\n\x21").status == proxyNeedMore
  # malformed
  check pr("GET / HTTP/1.1\r\n").status == proxyBad
  check pr("PROXY TCP4 999.1.1.1 10.0.0.1 1 80\r\n").status == proxyBad
  check pr("PROXY TCP4 1.1.1.1 2.2.2.2 1 99999\r\n").status == proxyBad
  check pr("PROXY TCP4 1.1.1.1 2.2.2.2 1 2 3\r\n").status == proxyBad
  check pr("PROXY TCP4 1.1.1.1 2.2.2.2 1\r\n").status == proxyBad
  check pr("PROXY  TCP4 1.1.1.1 2.2.2.2 1 2\r\n").status == proxyBad
  check pr("PROXY FOO 1.1.1.1 2.2.2.2 1 2\r\n").status == proxyBad
  check pr("PROXY TCP4 1.1.1.1 2.2.2.2 1 2\n").status == proxyBad
  # over-long line without CRLF
  var long = "PROXY TCP4 1.1.1.1 2.2.2.2 1 2"
  while long.len < 107:
    long.add('x')
  check pr(long).status == proxyNeedMore
  check pr(long & "y").status == proxyBad
  # valid v2 TCP4
  let v2 = toBytes("\r\n\r\n\0\r\nQUIT\n\x21\x11\x00\x0C" &
    "\xC0\x00\x02\x01\x0A\x00\x00\x02\x12\x34\x00\x50")
  r = parseProxyHeader(v2)
  check r.status == proxyOk
  check r.consumed == 28
  check r.srcIp == "192.0.2.1"
  # valid v2 TCP6
  let v6 = toBytes("\r\n\r\n\0\r\nQUIT\n\x21\x21\x00\x24" &
    "\x20\x01\x0D\xB8" & repeat("\x00", 11) & "\x01" &
    "\x20\x01\x0D\xB8" & repeat("\x00", 11) & "\x02" &
    "\x01\xBB\x1F\x90")
  r = parseProxyHeader(v6)
  check r.status == proxyOk
  check r.srcIp == "2001:db8::1"

# ── Integration ─────────────────────────────────────────────────────────────

proc runProxy(port: int, proxyOn: bool, chunks: seq[string],
              withHandler = true): tuple[raw: string, seenIp: string,
                                         hits: int] =
  ## Serve one connection; client sends `chunks` (split writes for the
  ## split-header test). Returns the raw bytes plus handler observations.
  let loop = newLoop()
  let server = newHttpServer(loop)
  server.proxyProtocol = proxyOn
  var seenIp = ""
  var hits = 0
  if withHandler:
    server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
      {.gcsafe.}:
        seenIp = req.getClientIp()
        inc hits
      res.send("ok")
  server.listen("127.0.0.1", port)
  var received = ""
  loop.connect("127.0.0.1", port,
    onConnect = proc(conn: Connection) =
      discard conn.send(chunks[0])
      for i in 1 ..< chunks.len:
        let part = chunks[i]
        discard loop.addTimer(100 * i) do (id: int):
          discard conn.send(part),
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
  (received, seenIp, hits)

const GetRoot = "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"

test "v1_tcp4_reports_source_ip":
  let (raw, seenIp, hits) = runProxy(19910, true,
    @["PROXY TCP4 192.168.1.10 10.0.0.1 12345 80\r\n" & GetRoot])
  check hits == 1
  check seenIp == "192.168.1.10"
  check raw.startsWith("HTTP/1.1 200")

test "v1_unknown_keeps_socket_peer":
  let (raw, seenIp, hits) = runProxy(19911, true,
    @["PROXY UNKNOWN\r\n" & GetRoot])
  check hits == 1
  check seenIp == "127.0.0.1"
  check raw.startsWith("HTTP/1.1 200")

test "v2_tcp4_reports_source_ip":
  let pre = "\r\n\r\n\0\r\nQUIT\n\x21\x11\x00\x0C" &
    "\xC0\x00\x02\x01\x0A\x00\x00\x02\x12\x34\x00\x50"
  let (raw, seenIp, hits) = runProxy(19912, true, @[pre & GetRoot])
  check hits == 1
  check seenIp == "192.0.2.1"
  check raw.startsWith("HTTP/1.1 200")

test "v2_tcp6_reports_source_ip":
  let pre = "\r\n\r\n\0\r\nQUIT\n\x21\x21\x00\x24" &
    "\x20\x01\x0D\xB8" & repeat("\x00", 11) & "\x01" &
    "\x20\x01\x0D\xB8" & repeat("\x00", 11) & "\x02" &
    "\x01\xBB\x1F\x90"
  let (raw, seenIp, hits) = runProxy(19913, true, @[pre & GetRoot])
  check hits == 1
  check seenIp == "2001:db8::1"
  check raw.startsWith("HTTP/1.1 200")

test "split_header_two_writes":
  let (raw, seenIp, hits) = runProxy(19914, true,
    @["PROXY TCP4 192.168.7.7 10.0.0.1 9", "999 80\r\n" & GetRoot])
  check hits == 1
  check seenIp == "192.168.7.7"
  check raw.startsWith("HTTP/1.1 200")

test "garbage_preface_is_400":
  let (raw, seenIp, hits) = runProxy(19915, true, @["GARBAGE\r\n" & GetRoot])
  check hits == 0
  check seenIp == ""
  check raw.startsWith("HTTP/1.1 400")

test "flag_off_preface_is_plain_400":
  # Flag off: the preface hits the HTTP parser as garbage — byte-identical
  # to today's behavior for a bad request line.
  let (raw, seenIp, hits) = runProxy(19916, false,
    @["PROXY TCP4 192.168.1.10 10.0.0.1 12345 80\r\n" & GetRoot])
  check hits == 0
  check seenIp == ""
  check raw.startsWith("HTTP/1.1 400")

test "pipelined_remainder_same_read":
  let two = "GET / HTTP/1.1\r\nHost: x\r\n\r\n" &
    "GET /2 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
  let (raw, seenIp, hits) = runProxy(19917, true,
    @["PROXY TCP4 10.9.9.9 10.0.0.1 111 80\r\n" & two])
  check hits == 2
  check seenIp == "10.9.9.9"
  check raw.count("HTTP/1.1 200") == 2
