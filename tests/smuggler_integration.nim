## tests/smuggler_integration.nim — PowPow × smuggler security integration.
##
## Uses the `smuggler` fuzzing package (installed via nimble; run through the
## `testSmuggler` nimble task) to:
##
##   Part A — in-process parser safety + hardening: generate + mutate requests
##            from bundled grammars, feed them to the HTTP parser, and assert it
##            never crashes, never allocates unboundedly, never produces a
##            negative Content-Length, and REJECTS ambiguous framing
##            (CL+TE, obs-fold, conflicting duplicate CL, 2^63 CL, ...).
##
##   Part B — deterministic live parser-diff: send the generated attack
##            followed by a tagged probe over one keep-alive connection and
##            verify powpow's observed response count exactly matches what its
##            own parser declares (single-segment delivery makes this
##            deterministic). A real desync shows up as a missing response
##            (probe consumed/dropped) or a ghost response.

import std/[unittest, strutils, os]
import std/httpcore
import ../src/powpow
import smuggler

const
  MaxBody = 1_048_576i64      # matches the live server's cap
  PartAIterations = 500
  PartBIterations = 1000

proc grammarPaths(): seq[string] =
  ## Absolute paths to the bundled fuzz grammars (tests run from the package
  ## root, e.g. `nimble testSmuggler`).
  let dir = getCurrentDir() / "tests" / "fuzz"
  result.add(dir / "request-line.cfg")
  result.add(dir / "headers.cfg")
  result.add(dir / "body.cfg")

# ══════════════════════════════════════════════════════════════════════
# Expected-classification helpers (shared by Part A and Part B)
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

proc simResponseCount(raw: string): int =
  ## Expected number of responses powpow would emit for `raw` (attack + probe),
  ## mirroring handleConnectionData's pipeline loop + final error handling.
  ## Returns -1 if feeding raised a Defect.
  let parser = newHttpParser()
  parser.maxBodySize = MaxBody
  try:
    parser.feed(raw)
  except Defect:
    return -1
  var n = 0
  while parser.isComplete():
    inc n
    if parser.connectionClose:
      # powpow honours Connection: close — it closes after this response and
      # never dispatches the remaining (probe) bytes.
      parser.resetForNext()
      return n
    parser.resetForNext()
    parser.tryAdvance()
  if parser.isError():
    inc n
  n

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
# Part B — deterministic live parser-diff via smuggler's sockets
# ══════════════════════════════════════════════════════════════════════

when not defined(windows):
  import std/typedthreads

  const SmugglerPort = 29952

  var smugglerChan: Channel[string]

  proc makeProbe(tag: string): string =
    "GET /_PROBE_" & tag & " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

  proc countHttpResponses(buf: string): int =
    ## Count HTTP response status lines in the received bytes. Responses always
    ## start with `HTTP/1.` and the echo bodies never contain that substring.
    var i = 0
    while i + 7 <= buf.len:
      if buf[i] == 'H' and buf[i + 1] == 'T' and buf[i + 2] == 'T' and
         buf[i + 3] == 'P' and buf[i + 4] == '/' and buf[i + 5] == '1' and
         buf[i + 6] == '.':
        inc result
      inc i
    result

  proc runOne(conn: smuggler.Conn; attack, probe: string;
              expected: int): tuple[count: int; buf: string] =
    ## Send attack+probe in ONE write (single segment on loopback), read up to
    ## `expected` response reads (+1 ghost probe), and count responses by status
    ## line (readPending may coalesce several into one buffer).
    conn.sendRaw(attack & probe)
    var buf = ""
    let readLimit = if expected >= 2: expected + 1 else: 1
    for _ in 0 ..< readLimit:
      let r = conn.readPending()
      if r.raw.len == 0:
        break
      buf.add(r.raw)
    (countHttpResponses(buf), buf)

  type SmugSample* = tuple
    raw, probe, tag: string
    expected: int

  proc buildCorpus(paths: seq[string]; iters: int): tuple[samples: seq[SmugSample]; defects: seq[string]] =
    ## Precompute the network-test corpus in the main thread: for each generated
    ## request that is complete-or-rejected under powpow's own parser, compute
    ## the expected response count for (attack + probe) and stage the sample.
    for cfgPath in paths:
      let g = smuggler.parseGrammarFile(cfgPath)
      for s in 0 ..< iters:
        let raw = smuggler.generate(g, s.int64)
        let exp = classifyExpected(raw)
        if exp == expDefect:
          result.defects.add("DEFECT seed=" & $s & " " & cfgPath)
          continue
        if exp == expIncomplete:
          continue  # parser-level behaviour; covered by Part A
        let tag = "T" & $(result.samples.len + 1) & "_" & $s
        let probe = makeProbe(tag)
        let expected = simResponseCount(raw & probe)
        if expected < 1:
          result.defects.add("SIM expected=" & $expected & " seed=" & $s & " " & cfgPath)
          continue
        result.samples.add((raw, probe, tag, expected))

  proc runLive(samples: seq[SmugSample]) {.thread.} =
    ## Hammer the powpow server with the precomputed corpus and verify each
    ## sample's wire behaviour against the expected response count. Ships a
    ## compact report back over `smugglerChan`.
    var
      total, mismatches, ghosts = 0
      fails: seq[string] = @[]
    for sample in samples:
      inc total
      var conn: smuggler.Conn
      try:
        conn = smuggler.open("127.0.0.1", SmugglerPort, timeoutMs = 800)
      except CatchableError:
        fails.add("CONNECT tag=" & sample.tag)
        continue
      let r = runOne(conn, sample.raw, sample.probe, sample.expected)
      smuggler.close(conn)
      if sample.expected >= 2:
        # A complete request must yield exactly one response per request
        # boundary (attack + probe), never fewer (a swallowed/dropped response)
        # and never more (a ghost).
        if r.count > sample.expected:
          inc ghosts
          fails.add("GHOST tag=" & sample.tag & " exp=" & $sample.expected & " got=" & $r.count)
        elif r.count < sample.expected:
          inc mismatches
          fails.add("MISSING tag=" & sample.tag & " exp=" & $sample.expected & " got=" & $r.count & " raw=" & sample.raw.escape() & " buf=" & r.buf.escape())
      else:
        # expected == 1: rejected attack → a single 4xx. A separately-arriving
        # probe may add a second response, so accept {1, 2}.
        if r.count == 0:
          inc mismatches
          fails.add("MISSING tag=" & sample.tag & " exp=1 got=0")
        elif r.count > 2:
          inc ghosts
          fails.add("GHOST tag=" & sample.tag & " exp=1 got=" & $r.count)
    var report = "total=" & $total & " mismatches=" & $mismatches &
                 " ghosts=" & $ghosts
    for f in fails:
      report.add("\n  " & f)
    smugglerChan.send(report)

  test "live server: wire behaviour matches the parser (no desync)":
    let corpus = buildCorpus(grammarPaths(), PartBIterations)
    echo "  Part B corpus: samples=", corpus.samples.len, " defects=", corpus.defects.len

    let loop = newLoop()
    var server = newHttpServer(loop)
    server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
      {.gcsafe.}:
        res.status(Http200).send("echo " & req.getPath())
    server.maxBodySize = MaxBody
    server.readTimeoutMs = 150
    server.timeoutSweepMs = 50
    server.setKeepAliveTimeout(150)
    server.listen("127.0.0.1", SmugglerPort)

    # Warm up accepts so the worker's first connects succeed.
    for _ in 0 ..< 100:
      loop.poll(2)

    smugglerChan.open()
    var th: Thread[seq[SmugSample]]
    createThread(th, runLive, corpus.samples)

    var polls = 0
    while smugglerChan.peek() == 0 and polls < 60_000:
      loop.poll(5)
      inc polls

    let report = if smugglerChan.peek() > 0: smugglerChan.recv() else: ""
    joinThread(th)
    server.close()
    loop.close()
    smugglerChan.close()

    echo "  Part B report:"
    for ln in report.splitLines():
      echo "    ", ln

    doAssert report.len > 0, "worker produced no report (timeout?)"

    var
      total, mismatches, ghosts = 0
    for kv in report.split(' '):
      let kvp = kv.split('=')
      if kvp.len != 2: continue
      let v = try: parseInt(kvp[1]) except ValueError: -1
      case kvp[0]
      of "total": total = v
      of "mismatches": mismatches = v
      of "ghosts": ghosts = v
      else: discard

    doAssert total > 0, "corpus produced no network-testable requests"
    doAssert corpus.defects.len == 0,
      "parser defects during Part B corpus build:\n  " & corpus.defects.join("\n  ")
    doAssert mismatches == 0, "response-count mismatches: " & $mismatches
    doAssert ghosts == 0, "ghost responses: " & $ghosts
