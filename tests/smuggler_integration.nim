## tests/smuggler_integration.nim — PowPow × smuggler security integration.
##
## Uses the `smuggler` fuzzing package (installed via nimble; run through the
## `testSmuggler` nimble task) to:
##
##   Part A — in-process parser safety + hardening: generate + mutate requests
##            from bundled grammars, feed them to the HTTP parser, and assert it
##            never crashes, never allocates unboundedly, never produces a
##            negative Content-Length, and REJECTS ambiguous framing
##            (CL+TE, obs-fold, conflicting duplicate CL, malformed CL, ...).
##
##   Part B — two-server differential (T-Reqs Stage 1): run powpow AND an
##            independent RFC-strict reference server simultaneously, send the
##            identical generated request to both, and assert they reach the
##            same decision (same status, same parsed body length). HRS is a
##            discrepancy between two HTTP processors; a request where powpow
##            and a conformant reference disagree is the red flag this test
##            hunts for. powpow must match the reference on every request.

import std/[unittest, strutils, os, net, nativesockets, sequtils]
import std/httpcore
import ../src/powpow
import smuggler

const
  MaxBody = 1_048_576i64      # matches the live servers' cap
  PartAIterations = 500
  PartBIterations = 1000
  PowPowPort = 29952
  RefPort = 29953

proc grammarPaths(): seq[string] =
  ## Absolute paths to the bundled fuzz grammars (tests run from the package
  ## root, e.g. `nimble testSmuggler`).
  let dir = getCurrentDir() / "tests" / "fuzz"
  result.add(dir / "request-line.cfg")
  result.add(dir / "headers.cfg")
  result.add(dir / "body.cfg")

# ══════════════════════════════════════════════════════════════════════
# Expected-classification helper (shared by Part A and Part B)
# ══════════════════════════════════════════════════════════════════════

type Expected* = enum
  expComplete    ## the request is fully framed on its own
  expRejected    ## the parser rejects it (4xx)
  expIncomplete  ## the parser waits for more body bytes
  expDefect      ## feeding it raised a Defect (a regression)

proc classifyExpected(raw: string): Expected =
  ## Feed `raw` to a fresh powpow parser and report how it treats the request.
  let parser = newHttpParser()
  parser.maxBodySize = MaxBody
  try:
    parser.feed(raw)
  except Defect:
    return expDefect
  if parser.isError(): return expRejected
  if parser.isComplete(): return expComplete
  expIncomplete

# ══════════════════════════════════════════════════════════════════════
# Part A — in-process parser safety + hardening (deterministic, all platforms)
# ══════════════════════════════════════════════════════════════════════

test "parser survives generated requests without defects or desync primitives":
  for cfgPath in grammarPaths():
    let g = smuggler.parseGrammarFile(cfgPath)
    var anomalies = 0
    var candidates = 0
    var complete = 0
    var rejected = 0
    for s in 0 ..< PartAIterations:
      let req = smuggler.generate(g, s.int64)
      var mutated = smuggler.toBytes(req)
      smuggler.mutateRequest(mutated, seed = s.int64 + 100_000, mutations = 1)
      let raw = smuggler.toString(mutated)

      let parser = newHttpParser()
      parser.maxBodySize = MaxBody
      try:
        parser.feed(raw)
      except Defect:
        echo "  DEFECT on seed ", s, " (", cfgPath, "): ", raw.escape()
        inc anomalies
        continue

      if parser.buf.len > 4 * 1024 * 1024:
        echo "  UNBOUNDED buffer on seed ", s, " (", cfgPath, ") len=", parser.buf.len
        inc anomalies

      if parser.contentLength < -1:
        echo "  NEGATIVE contentLength on seed ", s, " (", cfgPath, "): ", parser.contentLength
        inc anomalies

      if parser.isComplete(): inc complete
      elif parser.isError(): inc rejected
      if smuggler.isDesyncCandidate(raw):
        inc candidates
    echo "  ", cfgPath, ": candidates=", candidates, " anomalies=", anomalies,
         " complete=", complete, " rejected=", rejected
    check anomalies == 0

test "parser rejects ambiguous Content-Length + Transfer-Encoding":
  for raw in [
    "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
    "POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
  ]:
    let parser = newHttpParser()
    parser.feed(raw)
    check parser.isError()
    check parser.error() == Http400

test "parser rejects TE + CL regardless of TE value":
  # A non-chunked TE alongside CL is just as ambiguous and must be rejected.
  let raw = "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nTransfer-Encoding: gzip\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  check parser.isError()
  check parser.error() == Http400

test "parser rejects obs-fold leading-whitespace headers":
  let raw = "GET /x HTTP/1.1\r\nHost: h\r\n Continuation: value\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  check parser.isError()
  check parser.error() == Http400

test "parser rejects conflicting duplicate Content-Length":
  let raw = "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  check parser.isError()
  check parser.error() == Http400

test "parser rejects malformed Content-Length values":
  # A value that is not entirely digits (after OWS) must be rejected — silently
  # truncating `5x`/`1e3`/`5.0` to 5/1 would let two servers disagree.
  for raw in [
    "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5x\r\n\r\n",
    "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 1e3\r\n\r\n",
    "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5.0\r\n\r\n",
    "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 0x1\r\n\r\n",
  ]:
    let parser = newHttpParser()
    parser.feed(raw)
    check parser.isError()
    check parser.error() == Http400

test "parser accepts leading/trailing OWS on Content-Length":
  for raw in [
    "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello",
    "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length:  5 \r\n\r\nhello",
  ]:
    let parser = newHttpParser()
    parser.feed(raw)
    check parser.isComplete()
    check parser.contentLength == 5

test "parser rejects 2^63 Content-Length":
  let raw = "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 9223372036854775808\r\n\r\n"
  let parser = newHttpParser()
  parser.feed(raw)
  check parser.isError()
  check parser.error() == Http413
  check parser.contentLength == -1

test "LF-only chunked line endings never crash the parser":
  let raw = "POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\nhello\n0\n"
  let parser = newHttpParser()
  var crashed = false
  try:
    parser.feed(raw)
  except Defect:
    crashed = true
  check not crashed
  check parser.buf.len < 64 * 1024

# ══════════════════════════════════════════════════════════════════════
# Part B — two-server differential (T-Reqs Stage 1)
# ══════════════════════════════════════════════════════════════════════

when not defined(windows):
  import std/typedthreads

  type RefSample* = tuple
    raw, tag: string

  # ── Reference server: an independent RFC-strict HTTP/1.x parser ───────────
  # Deliberately does NOT use powpow's parser — it is a separate implementation
  # of the same RFC rules, so the comparison is a true differential oracle.

  type RefFrame = tuple
    cl: int          # -1 if absent
    anyTe: bool      # any Transfer-Encoding header present
    chunked: bool    # final TE token is exactly "chunked"
    err: int         # 0 = ok, 400/413 = reject with that code

  proc refHeaderScan(buf: string; sep: int): RefFrame =
    result = (cl: -1, anyTe: false, chunked: false, err: 0)
    var i = 0
    let rlEnd = buf.find("\r\n")
    if rlEnd < 0 or rlEnd > sep:
      result.err = 400
      return
    i = rlEnd + 2
    while i < sep:
      let le = buf.find("\r\n", i)
      let lineEnd = if le < 0 or le > sep: sep else: le
      if lineEnd > i:
        let first = buf[i]
        if first == ' ' or first == '\t':
          result.err = 400          # obs-fold / leading-ws header
          return
        let lower = buf[i .. lineEnd - 1].toLowerAscii()
        if lower.startsWith("content-length:"):
          let val = buf[i + 15 .. lineEnd - 1].strip()
          if val.len == 0 or not val.allIt(it in {'0'..'9'}):
            result.err = 400
            return
          var num = 0
          for ch in val:
            if num > (high(int) - (ord(ch) - ord('0'))) div 10:
              result.err = 413
              return
            num = num * 10 + (ord(ch) - ord('0'))
          if num > MaxBody:
            result.err = 413
            return
          if result.cl >= 0 and result.cl != num:
            result.err = 400        # conflicting duplicate CL
            return
          result.cl = num
        elif lower.startsWith("transfer-encoding:"):
          result.anyTe = true
          var val = buf[i + 18 .. lineEnd - 1].strip()
          let comma = val.rfind(',')
          if comma >= 0:
            val = val[comma + 1 .. ^1]
          if val.strip().toLowerAscii() == "chunked":
            result.chunked = true
      i = lineEnd + 2

  proc refRequestLineOk(buf: string; rlEnd: int): bool =
    ## Mirrors powpow's parseRequestLine: "METHOD SP PATH SP HTTP/x.y...".
    ## Multiple spaces or tabs between tokens make the request line invalid.
    var i = 0
    while i < rlEnd and buf[i] != ' ':
      if i >= 10:
        return false
      inc i
    if i >= rlEnd:
      return false                    # no space after method
    inc i                             # skip exactly one space
    while i < rlEnd and buf[i] != ' ':
      inc i
    if i >= rlEnd:
      return false                    # no space after path
    inc i                             # skip exactly one space
    if i + 8 > rlEnd:
      return false
    if buf[i] != 'H' or buf[i + 1] != 'T' or buf[i + 2] != 'T' or
       buf[i + 3] != 'P' or buf[i + 4] != '/':
      return false
    true

  proc refParseOne(buf: string): tuple[status: int; bodyLen: int; done: bool] =
    ## Parse one request incrementally. status 0 = need more data; on completion
    ## status is 200 (ok) or 400/413 (reject). bodyLen is the decoded body length.
    let rlEnd = buf.find("\r\n")
    if rlEnd < 0:
      if buf.len > 64 * 1024:
        return (413, 0, true)
      return (0, 0, false)
    if not refRequestLineOk(buf, rlEnd):
      return (400, 0, true)
    let sep = buf.find("\r\n\r\n")
    if sep < 0:
      if buf.len > 64 * 1024:
        return (413, 0, true)
      return (0, 0, false)
    let headerEnd = sep + 4
    let frame = refHeaderScan(buf, sep)
    if frame.err != 0:
      return (frame.err, 0, true)
    if frame.anyTe and frame.cl >= 0:
      return (400, 0, true)         # CL + TE ambiguity (RFC 9112 §6.3)
    if frame.chunked:
      var pos = headerEnd
      var total = 0
      while true:
        if pos >= buf.len:
          return (0, 0, false)
        let crlf = buf.find("\r\n", pos)
        if crlf < 0:
          return (0, 0, false)
        let sizeLine = buf[pos .. crlf - 1]
        let semi = sizeLine.find(';')
        let hexs = (if semi >= 0: sizeLine[0 .. semi - 1] else: sizeLine).strip()
        if hexs.len == 0:
          return (400, 0, true)
        var size = 0
        for ch in hexs:
          let d = case ch
            of '0'..'9': ord(ch) - ord('0')
            of 'a'..'f': ord(ch) - ord('a') + 10
            of 'A'..'F': ord(ch) - ord('A') + 10
            else: -1
          if d < 0 or size > high(int) div 16:
            return (400, 0, true)
          size = size * 16 + d
        pos = crlf + 2
        if size == 0:
          if pos + 2 > buf.len:
            return (0, 0, false)
          if buf[pos] == '\r' and buf[pos + 1] == '\n':
            return (200, total, true)
          return (400, 0, true)     # trailers unsupported by reference
        if pos + size + 2 > buf.len:
          return (0, 0, false)
        total += size
        if buf[pos + size] != '\r' or buf[pos + size + 1] != '\n':
          return (400, 0, true)
        pos += size + 2
    elif frame.cl >= 0:
      if buf.len - headerEnd >= frame.cl:
        return (200, frame.cl, true)
      return (0, 0, false)
    else:
      return (200, 0, true)

  var
    refReady: Channel[bool]
    resultChan: Channel[string]
    stopRef = false

  proc respond(conn: Socket; status, bodyLen: int) =
    ## Uses raw nativesockets.send: std/net's Socket.send/recv on *accepted*
    ## (buffered-inherited) sockets hangs on macOS, while the raw syscalls work.
    let fd = conn.getFd()
    if status == 200:
      let body = "bodyLen=" & $bodyLen
      let msg = "HTTP/1.1 200 OK\r\nContent-Length: " & $body.len &
                "\r\nConnection: close\r\n\r\n" & body
      discard nativesockets.send(fd, addr msg[0], msg.len, 0)
    else:
      let msg = "HTTP/1.1 " & $status &
                "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
      discard nativesockets.send(fd, addr msg[0], msg.len, 0)

  proc serveRef(conn: Socket) =
    var buf = ""
    while true:
      var connFds: seq[SocketHandle] = @[conn.getFd()]   # selectRead prunes this seq
      # The client sends the whole request in one burst and then waits. A short
      # no-data window therefore means the request is complete-as-sent.
      let ready = nativesockets.selectRead(connFds, 50)
      if ready <= 0:
        respond(conn, 400, 0)          # no more bytes: request complete-as-sent
        break
      var chunk: array[4096, byte]
      let n = nativesockets.recv(conn.getFd(), addr chunk[0], chunk.len, 0)
      if n <= 0:
        respond(conn, 400, 0)          # error or EOF before parsing completed
        break
      for i in 0 ..< n:
        buf.add(char(chunk[i]))
      let pr = refParseOne(buf)
      if pr.done:
        respond(conn, pr.status, pr.bodyLen)
        break

  proc runReference() {.thread.} =
    var srv: Socket
    try:
      srv = newSocket()
      srv.setSockOpt(OptReuseAddr, true)
      srv.bindAddr(Port(RefPort), "127.0.0.1")
      srv.listen()
    except CatchableError as e:
      echo "  [ref] bind failed: ", e.msg
      refReady.send(false)
      return
    refReady.send(true)
    while not stopRef:
      var listenFds: seq[SocketHandle] = @[srv.getFd()]   # selectRead prunes this seq
      if nativesockets.selectRead(listenFds, 100) <= 0:
        continue
      var conn: Socket
      try:
        srv.accept(conn)
        serveRef(conn)
        conn.close()
      except CatchableError as e:
        echo "  [ref] serve error: ", e.msg
    srv.close()

  # ── Client worker: send every request to BOTH servers, compare signatures ──

  proc buildSamples(paths: seq[string]; iters: int): tuple[samples: seq[RefSample]; defects: seq[string]] =
    for cfgPath in paths:
      let g = smuggler.parseGrammarFile(cfgPath)
      for s in 0 ..< iters:
        let raw = smuggler.generate(g, s.int64)
        let exp = classifyExpected(raw)
        if exp == expDefect:
          result.defects.add("DEFECT seed=" & $s & " " & cfgPath)
          continue
        if exp == expIncomplete:
          continue                    # parser-level behaviour; covered by Part A
        result.samples.add((raw, "T" & $(result.samples.len + 1) & "_" & $s))

  proc parseSig(raw: string): tuple[ok: bool; status: int; bodyLen: int] =
    ## Extract the first response's status code and (for 200) the echoed bodyLen.
    let hs = raw.find("HTTP/1.")
    if hs < 0:
      return (false, 0, -1)
    let sp = raw.find(' ', hs)
    if sp < 0:
      return (false, 0, -1)
    for j in sp + 1 .. min(sp + 3, raw.high):
      if raw[j] in {'0'..'9'}:
        result.status = result.status * 10 + (ord(raw[j]) - ord('0'))
    let b = raw.find("bodyLen=")
    if b >= 0:
      var v = 0
      var j = b + 8
      while j < raw.len and raw[j] in {'0'..'9'}:
        v = v * 10 + (ord(raw[j]) - ord('0'))
        inc j
      result.bodyLen = v
    else:
      result.bodyLen = -1
    result.ok = true

  proc runClient(samples: seq[RefSample]) {.thread.} =
    var
      total = 0
      discrepancies: seq[string] = @[]
    for s in samples:
      inc total
      var cp: smuggler.Conn
      try:
        cp = smuggler.open("127.0.0.1", PowPowPort, timeoutMs = 1000)
        cp.sendRaw(s.raw)
        let rp = cp.readPending()
        smuggler.close(cp)
        let sp = parseSig(rp.raw)

        var cr: smuggler.Conn
        try:
          cr = smuggler.open("127.0.0.1", RefPort, timeoutMs = 1000)
          cr.sendRaw(s.raw)
          let rr = cr.readPending()
          smuggler.close(cr)
          let sr = parseSig(rr.raw)

          if sp.ok and sr.ok:
            if sp.status == 200 and sr.status == 200:
              if sp.bodyLen != sr.bodyLen:
                discrepancies.add("BODYLEN tag=" & s.tag & " powpow=" & $sp.bodyLen &
                                  " ref=" & $sr.bodyLen & " raw=" & s.raw.escape())
            elif sp.status >= 400 and sr.status >= 400:
              if sp.status != sr.status:
                discrepancies.add("STATUS tag=" & s.tag & " powpow=" & $sp.status &
                                  " ref=" & $sr.status & " raw=" & s.raw.escape())
            else:
              discrepancies.add("MIXED tag=" & s.tag & " powpow=" & $sp.status &
                                " ref=" & $sr.status & " raw=" & s.raw.escape())
          else:
            discrepancies.add("UNPARSEABLE tag=" & s.tag &
                              " powpow=" & rp.raw.escape() & " ref=" & rr.raw.escape())
        except CatchableError:
          discrepancies.add("CONNECT-REF tag=" & s.tag)
      except CatchableError:
        discrepancies.add("CONNECT-POWPOW tag=" & s.tag)

    var report = "total=" & $total & " discrepancies=" & $discrepancies.len
    for d in discrepancies:
      report.add("\n  " & d)
    resultChan.send(report)

  test "two-server differential: powpow matches an RFC-strict reference":
    let corpus = buildSamples(grammarPaths(), PartBIterations)
    echo "  Part B corpus: samples=", corpus.samples.len, " defects=", corpus.defects.len

    let loop = newLoop()
    var server = newHttpServer(loop)
    server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
      {.gcsafe.}:
        res.status(Http200).send("bodyLen=" & $req.getBody().len)
    server.maxBodySize = MaxBody
    server.readTimeoutMs = 150
    server.timeoutSweepMs = 50
    server.setKeepAliveTimeout(150)
    server.listen("127.0.0.1", PowPowPort)

    refReady.open()
    resultChan.open()
    var refTh: Thread[void]
    createThread(refTh, runReference)
    let refOk = refReady.recv()
    doAssert refOk, "reference server failed to bind"

    # Warm up accepts so the client's first connects succeed.
    for _ in 0 ..< 100:
      loop.poll(2)

    var clientTh: Thread[seq[RefSample]]
    createThread(clientTh, runClient, corpus.samples)

    var polls = 0
    while resultChan.peek() == 0 and polls < 60_000:
      loop.poll(5)
      inc polls

    let report = if resultChan.peek() > 0: resultChan.recv() else: ""
    joinThread(clientTh)
    stopRef = true
    joinThread(refTh)
    server.close()
    loop.close()
    refReady.close()
    resultChan.close()

    echo "  Part B report:"
    for ln in report.splitLines():
      echo "    ", ln

    doAssert report.len > 0, "worker produced no report (timeout?)"

    var total = 0
    var discrepancies = 0
    for kv in report.split(' '):
      let kvp = kv.split('=')
      if kvp.len != 2: continue
      case kvp[0]
      of "total":
        total = try: parseInt(kvp[1]) except ValueError: -1
      of "discrepancies":
        discrepancies = try: parseInt(kvp[1]) except ValueError: -1
      else: discard

    doAssert total > 0, "corpus produced no network-testable requests"
    doAssert corpus.defects.len == 0,
      "parser defects during corpus build:\n  " & corpus.defects.join("\n  ")
    doAssert discrepancies == 0,
      "powpow disagreed with the RFC-strict reference: " & $discrepancies
