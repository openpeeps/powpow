## tests/test_smuggler_integration.nim — PowPow × smuggler security integration.
##
## Uses the `smuggler` fuzzing package (installed via nimble; run through the
## `test-smuggler` nimble task) to:
##
##   Part A — in-process parser safety: generate + mutate requests from a
##            bundled grammar, feed them to the HTTP parser, and assert it never
##            crashes, never allocates unboundedly, and never produces a negative
##            Content-Length (the request-desync primitive).
##
##   Part B — live two-request desync: run the `smuggler` CLI binary against a
##            powpow HTTP server and assert zero detected desyncs.

import std/[unittest, strutils, osproc, os]
import std/httpcore
import ../src/powpow
import smuggler

proc grammarPath(): string =
  ## Absolute path to the bundled fuzz grammar (tests are run from the package
  ## root, e.g. `nimble testSmuggler`).
  getCurrentDir() / "tests" / "fuzz" / "request-line.cfg"

# ══════════════════════════════════════════════════════════════════════
# Part A — in-process parser safety (deterministic, all platforms)
# ══════════════════════════════════════════════════════════════════════

test "parser survives generated requests without defects or desync primitives":
  let g = smuggler.parseGrammarFile(grammarPath())
  var anomalies = 0
  var candidates = 0
  for s in 0 ..< 500:
    let req = smuggler.generate(g, s.int64)
    var mutated = smuggler.toBytes(req)
    smuggler.mutateRequest(mutated, seed = s.int64 + 100_000, mutations = 1)
    let raw = smuggler.toString(mutated)

    let parser = newHttpParser()
    parser.maxBodySize = 1_048_576
    try:
      parser.feed(raw)
    except Defect:
      # Range/Overflow/Index defects = a regression the fuzzer must catch
      echo "  DEFECT on seed ", s, ": ", raw.escape()
      inc anomalies
      continue

    # No allocation-before-limits regression: buffer must stay bounded
    if parser.buf.len > 4 * 1024 * 1024:
      echo "  UNBOUNDED buffer on seed ", s, " len=", parser.buf.len
      inc anomalies

    # No negative Content-Length (the 2^63 wrap desync primitive)
    if parser.contentLength < -1:
      echo "  NEGATIVE contentLength on seed ", s, ": ", parser.contentLength
      inc anomalies

    if smuggler.isDesyncCandidate(raw):
      inc candidates
  echo "  Part A: candidates=", candidates, " anomalies=", anomalies
  check anomalies == 0

# ══════════════════════════════════════════════════════════════════════
# Part B — live two-request desync via the smuggler CLI binary
# ══════════════════════════════════════════════════════════════════════

when not defined(windows):
  import std/typedthreads

  const SmugglerPort = 29951

  var smugglerChan: Channel[string]

  proc runSmuggler(cmd: string) {.thread.} =
    ## Run the smuggler CLI against powpow and ship its output back.
    let (output, _) = execCmdEx(cmd)
    smugglerChan.send(output)

  test "live server: no two-request desyncs detected by smuggler":
    let loop = newLoop()
    var server = newHttpServer(loop)
    server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
      res.status(Http200).send("ok")
    server.listen("127.0.0.1", SmugglerPort)

    smugglerChan.open()
    let smugBin = if findExe("smuggler").len > 0: findExe("smuggler")
                  else: getHomeDir() / ".nimble" / "bin" / "smuggler"
    let cmd = smugBin & " -g " & grammarPath() &
              " -t 127.0.0.1:" & $SmugglerPort &
              " -n 100 -s 4242"
    var th: Thread[string]
    createThread(th, runSmuggler, cmd)

    # Pump the event loop while the smuggler binary hammers the server
    var polls = 0
    while smugglerChan.peek() == 0 and polls < 40_000:
      loop.poll(5)
      inc polls

    let output = if smugglerChan.peek() > 0: smugglerChan.recv() else: ""
    joinThread(th)
    server.close()
    loop.close()

    echo "  Part B output:"
    for ln in output.splitLines():
      echo "    ", ln

    # Parse the "possible desyncs: N / M" summary line
    var desyncs = -1
    for ln in output.splitLines():
      let low = ln.toLowerAscii()
      let key = "possible desyncs:"
      let idx = low.find(key)
      if idx >= 0:
        let rest = ln[idx + key.len .. ^1].strip()
        let sp = rest.find(' ')
        if sp > 0:
          try: desyncs = parseInt(rest[0 ..< sp])
          except ValueError: discard
    doAssert desyncs == 0,
      "smuggler reported possible desyncs: " & $desyncs
