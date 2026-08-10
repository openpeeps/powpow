## tests/test_bad_requests.nim — Extensive malformed-request battery.
##
## Two layers:
##   1. Parser-level: feed raw bytes into newHttpParser() and assert the
##      parse outcome / error code. Fast, deterministic, cross-platform.
##   2. Server-level: send raw bytes to a live HttpServer and assert on the
##      response status line and headers (Date, Content-Length, Connection).
##
## Expected codes:
##   - 400  malformed request (bad method token, bad header, malformed version)
##   - 505  well-formed but unsupported HTTP version (RFC 7230 §2.6)
##   - 413  body/CL size exceeded
##   - 431  header section too large / too many headers

import ../src/powpow
import std/[unittest, strutils, httpcore]

# ══════════════════════════════════════════════════════════════════════
# Layer 1 — parser helpers
# ══════════════════════════════════════════════════════════════════════

proc parseOutcome(raw: string): tuple[isErr: bool; errCode: HttpCode] =
  let p = newHttpParser()
  p.feed(raw)
  result = (p.isError(), if p.isError(): p.error() else: Http200)

template reject(raw: string; code: HttpCode) =
  let r = parseOutcome(raw)
  check r.isErr
  check r.errCode == code

template accept(raw: string) =
  let p = newHttpParser()
  p.feed(raw)
  check p.isComplete()

# ══════════════════════════════════════════════════════════════════════
# Layer 1 — request line: versions
# ══════════════════════════════════════════════════════════════════════

suite "bad request line — versions":

  test "well-formed but unsupported versions -> 505":
    reject("GET / HTTP/1.3\r\nHost: localhost\r\n\r\n", Http505)
    reject("GET / HTTP/1.4\r\nHost: localhost\r\n\r\n", Http505)
    reject("GET / HTTP/0.2\r\nHost: localhost\r\n\r\n", Http505)
    reject("GET / HTTP/0.9\r\nHost: localhost\r\n\r\n", Http505)
    reject("GET / HTTP/2.0\r\nHost: localhost\r\n\r\n", Http505)

  test "malformed versions -> 400":
    reject("GET / sdsP/4.3\r\nHost: localhost\r\n\r\n", Http400)
    reject("GET / HTTP/x.1\r\nHost: localhost\r\n\r\n", Http400)
    reject("GET / HTTP/1.x\r\nHost: localhost\r\n\r\n", Http400)
    reject("GET / HTTP/1.1x\r\nHost: localhost\r\n\r\n", Http400)
    reject("GET / HTTP/1.10\r\nHost: localhost\r\n\r\n", Http400)
    reject("GET / HTTP/1.1 garbage\r\nHost: localhost\r\n\r\n", Http400)
    reject("GET / HTTP\r\nHost: localhost\r\n\r\n", Http400)

  test "valid versions accepted":
    accept("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
    accept("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")

# ══════════════════════════════════════════════════════════════════════
# Layer 1 — request line: methods
# ══════════════════════════════════════════════════════════════════════

suite "bad request line — methods":

  test "near-miss method tokens -> 400":
    reject("GETTY / HTTP/1.1\r\nHost: localhost\r\n\r\n", Http400)
    reject("GIT / HTTP/1.1\r\nHost: localhost\r\n\r\n", Http400)
    reject("PET / HTTP/1.1\r\nHost: localhost\r\n\r\n", Http400)
    reject("PATCHX / HTTP/1.1\r\nHost: localhost\r\n\r\n", Http400)
    reject("POST9 / HTTP/1.1\r\nHost: localhost\r\n\r\n", Http400)
    reject("DELETE1 / HTTP/1.1\r\nHost: localhost\r\n\r\n", Http400)
    reject("HEADX / HTTP/1.1\r\nHost: localhost\r\n\r\n", Http400)
    reject("OPTION / HTTP/1.1\r\nHost: localhost\r\n\r\n", Http400)
    reject("CONNECT1 / HTTP/1.1\r\nHost: localhost\r\n\r\n", Http400)

  test "lowercase method token -> 400":
    reject("get / HTTP/1.1\r\nHost: localhost\r\n\r\n", Http400)
    reject("post / HTTP/1.1\r\nHost: localhost\r\n\r\n", Http400)

  test "empty method -> 400":
    reject(" / HTTP/1.1\r\nHost: localhost\r\n\r\n", Http400)

  test "valid methods accepted":
    accept("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    accept("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
    accept("PUT / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
    accept("PATCH / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
    accept("DELETE / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    accept("HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    accept("OPTIONS / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    accept("CONNECT / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    accept("TRACE / HTTP/1.1\r\nHost: localhost\r\n\r\n")

# ══════════════════════════════════════════════════════════════════════
# Layer 1 — request line: malformed targets
# ══════════════════════════════════════════════════════════════════════

suite "bad request line — targets":

  test "empty or missing target -> 400":
    reject("GET  HTTP/1.1\r\nHost: localhost\r\n\r\n", Http400)
    reject("GET HTTP/1.0\r\n\r\n", Http400)
    reject("HTTP/1.1\r\n\r\n", Http400)

  test "tab in request line -> 400":
    reject("GET\t/ HTTP/1.1\r\nHost: localhost\r\n\r\n", Http400)

# ══════════════════════════════════════════════════════════════════════
# Layer 1 — headers: malformed
# ══════════════════════════════════════════════════════════════════════

suite "bad headers — malformed lines":

  test "header without colon -> 400":
    reject("GET / HTTP/1.1\r\ninvalid header\r\n\r\n", Http400)
    reject("GET / HTTP/1.1\r\nHost localhost\r\n\r\n", Http400)

  test "empty field name -> 400":
    reject("GET / HTTP/1.1\r\n: value\r\n\r\n", Http400)

  test "obs-fold / leading whitespace -> 400":
    reject("GET / HTTP/1.1\r\n Foo: bar\r\n\r\n", Http400)
    reject("GET / HTTP/1.1\r\n\tFoo: bar\r\n\r\n", Http400)

  test "valid compact headers accepted (no space after colon)":
    accept("GET / HTTP/1.1\r\nhost:localhost\r\nconnection:close\r\n\r\n")

# ══════════════════════════════════════════════════════════════════════
# Layer 1 — headers: framing / smuggling
# ══════════════════════════════════════════════════════════════════════

suite "bad headers — framing (smuggling) -> 400":

  test "Content-Length + Transfer-Encoding":
    reject("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello",
           Http400)

  test "duplicate Content-Length mismatch":
    reject("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
           Http400)

  test "invalid Content-Length values":
    reject("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5x\r\n\r\nhello", Http400)
    reject("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1e3\r\n\r\nhello", Http400)
    reject("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: -1\r\n\r\n", Http400)
    reject("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5.0\r\n\r\nhello", Http400)

  test "Content-Length overflow -> 413":
    reject("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 99999999999999999999\r\n\r\n", Http413)

# ══════════════════════════════════════════════════════════════════════
# Layer 1 — headers: size limits -> 431
# ══════════════════════════════════════════════════════════════════════

suite "bad headers — size limits -> 431":

  test "oversized header section (no terminator)":
    reject("GET / HTTP/1.1\r\nHost: localhost\r\n" & repeat('X', 9000), Http431)

  test "too many headers":
    reject("GET / HTTP/1.1\r\n" & repeat("X: 1\r\n", 101) & "\r\n", Http431)

# ══════════════════════════════════════════════════════════════════════
# Layer 1 — garbage / binary
# ══════════════════════════════════════════════════════════════════════

suite "garbage / binary -> 400":

  test "non-ASCII garbage":
    reject("ààèèììòùù\r\n\r\n", Http400)

  test "null and control bytes":
    reject("\x00\x01\x02\r\n\r\n", Http400)

  test "request line with no version":
    reject("GET /\r\n\r\n", Http400)

# ══════════════════════════════════════════════════════════════════════
# Layer 2 — server-level response semantics
# ══════════════════════════════════════════════════════════════════════

const TestPort = 30001

let serverLoop = newLoop()
let testServer = newHttpServer(serverLoop)
testServer.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  {.gcsafe.}:
    res.status(Http200)
      .header("Content-Type", "text/plain; charset=utf-8")
      .send("ok")
testServer.listen("127.0.0.1", TestPort)

proc rawRequest(raw: string): string =
  ## Send raw bytes to the live server via the loop's own client and return
  ## the raw response text. Using loop.connect (event-driven reads) avoids the
  ## macOS SO_LINGER RST race that makes a blocking recv miss close-delivered
  ## responses.
  var resp = ""
  serverLoop.connect("127.0.0.1", TestPort,
    onConnect = proc(conn: Connection) =
      discard conn.send(raw)
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      resp.add cast[string](@data)
      conn.close()          # free the client fd / IOCP state
      serverLoop.stop()
    ,
    onClose = proc(conn: Connection) =
      serverLoop.stop()
  )
  discard serverLoop.addTimer(3000) do (id: int):
    serverLoop.stop()
  serverLoop.run()
  resp

suite "server — response semantics":

  test "HTTP/1.0 request gets a 200 with Content-Length (version stays 1.1)":
    let resp = rawRequest("GET / HTTP/1.0\r\nConnection: close\r\n\r\n")
    check resp.startsWith("HTTP/1.1 200")
    check resp.contains("Content-Length:")

  test "HTTP/1.1 response includes Date and Content-Length":
    let resp = rawRequest("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    check resp.startsWith("HTTP/1.1 200")
    check resp.contains("Date:")
    check resp.contains("Content-Length:")

  test "compact headers (no space after colon) are valid and close":
    let resp = rawRequest("GET / HTTP/1.1\r\nhost:localhost\r\nconnection:close\r\n\r\n")
    check resp.startsWith("HTTP/1.1 200")
    check resp.contains("Connection: close")

  test "unsupported version -> 505 on the wire":
    let resp = rawRequest("GET / HTTP/1.3\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    check resp.startsWith("HTTP/1.1 505")

  test "bad method token -> 400 on the wire":
    let resp = rawRequest("GETTY / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    check resp.startsWith("HTTP/1.1 400")

  test "header without colon -> 400 on the wire":
    let resp = rawRequest("GET / HTTP/1.1\r\ninvalid header\r\nConnection: close\r\n\r\n")
    check resp.startsWith("HTTP/1.1 400")
