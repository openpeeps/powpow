## tests/test_http_body_prearm.nim — Stream-before-buffer body handling (HTTP/1.1).
##
## Covers the roadmap item "Stream body bytes before first-packet buffering":
##   - Parser level: a pre-armed onHeadersComplete hook streams a large
##     single-packet Content-Length body straight to the callback — p.buf
##     never grows past ~headers (no whole-body allocation + copies).
##   - Parser level: chunked bodies decode incrementally once armed
##     (header pre-arm or threshold spill); small chunked stays buffered.
##   - Server level: large single-packet raw/multipart/chunked uploads land
##     in req.streamPath / req.streamer with byte-identical content, while
##     small bodies keep the buffered getBodyString fast path.

import ../src/powpow
import std/httpcore except HttpMethod
import std/[os, strutils, unittest]

# ── Parser-level: pre-arm machinery ──────────────────────────────────────────

test "test_prearm_single_packet_large_body_never_buffers":
  # 2 MB body arriving in ONE feed with the hook armed: everything streams,
  # p.buf stays at ~headers (proves no whole-body alloc + copy chain).
  const BodySize = 2 * 1024 * 1024
  let parser = newHttpParser()
  var collected = 0
  var dones = 0
  parser.onHeadersComplete = proc(p: HttpParser) {.closure.} =
    doAssert p.contentLength == BodySize
    p.onBodyData = proc(data: openArray[byte]; done: bool) {.closure.} =
      collected += data.len
      if done: inc dones
  var raw = "POST /big HTTP/1.1\r\nHost: x\r\nContent-Length: " & $BodySize & "\r\n\r\n"
  raw.setLen(raw.len + BodySize)
  for i in 0 ..< BodySize:
    raw[raw.len - BodySize + i] = 'A'
  let phase = parser.feed(raw)
  doAssert phase == PhaseComplete, "single-feed large body must complete, got " & $phase
  doAssert collected == BodySize, "all bytes streamed, got " & $collected
  doAssert dones == 1, "exactly one done=true"
  doAssert parser.bufLen < 32 * 1024, "buf holds headers only, got " & $parser.bufLen
  doAssert parser.buf.len < 64 * 1024, "no whole-body allocation, slab is " & $parser.buf.len

test "test_small_body_stays_buffered":
  # No hook armed: classic buffered path, getBodyString works.
  let parser = newHttpParser()
  let phase = parser.feed("POST /s HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello world")
  doAssert phase == PhaseComplete
  let req = HttpRequest(parser: parser, httpMethod: parser.methodCache)
  doAssert req.getBodyString() == "hello world"

test "test_chunked_threshold_spill_exact_once":
  # 200 KB chunked, threshold hook at 64 KB: decodes incrementally, spills
  # once, delivers every byte exactly once + terminal done.
  const ChunkCount = 20
  const ChunkSize = 10 * 1024
  let parser = newHttpParser()
  var collected = 0
  var dones = 0
  var spills = 0
  parser.onHeadersComplete = proc(p: HttpParser) {.closure.} =
    doAssert p.transferChunked
    p.bodyThreshold = 64 * 1024
    p.onBodyThreshold = proc(pp: HttpParser) {.closure.} =
      inc spills
      # Server equivalent: arm the counting callback; the parser flushes
      # already-decoded bytes itself via maybeSpillChunked.
      pp.onBodyData = proc(data: openArray[byte]; done: bool) {.closure.} =
        collected += data.len
        if done: inc dones
  var raw = "POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
  for _ in 0 ..< ChunkCount:
    raw &= "2800\r\n" & repeat('B', ChunkSize) & "\r\n"
  raw &= "0\r\n\r\n"
  # Feed split mid-stream to cross the threshold across feeds too.
  let cut = raw.len div 3
  doAssert parser.feed(raw.toOpenArrayByte(0, cut - 1)) == PhaseBody
  let phase = parser.feed(raw.toOpenArrayByte(cut, raw.high))
  doAssert phase == PhaseComplete, "chunked must complete, got " & $phase
  doAssert spills == 1, "threshold hook fires exactly once, got " & $spills
  doAssert collected == ChunkCount * ChunkSize, "every byte exactly once, got " & $collected
  doAssert dones == 1, "exactly one terminal done"
  doAssert parser.buf.len < 260 * 1024,
    "no decoded-copy growth: slab " & $parser.buf.len & " for 200KB body"

test "test_chunked_small_stays_buffered":
  # Small chunked with nothing armed (the server only arms the threshold
  # hook): buffered decode, no streaming mode, handler-visible via getBody.
  let parser = newHttpParser()
  let phase = parser.feed("POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
  doAssert phase == PhaseComplete
  doAssert not parser.streamingBody, "small chunked must not enter streaming mode"
  let req = HttpRequest(parser: parser, httpMethod: parser.methodCache)
  doAssert cast[string](req.getBody()) == "hello"

test "test_pipelined_request_after_streamed_body":
  # Streamed request followed by a pipelined second request in one packet:
  # leftover bytes must parse as the next request (hook re-fires per request).
  let parser = newHttpParser()
  var streamed = 0
  var hooks = 0
  parser.onHeadersComplete = proc(p: HttpParser) {.closure.} =
    inc hooks
    if p.contentLength > 100:
      p.onBodyData = proc(data: openArray[byte]; done: bool) {.closure.} =
        streamed += data.len
  var big = "POST /big HTTP/1.1\r\nHost: x\r\nContent-Length: 70000\r\n\r\n" &
            repeat('Q', 70000)
  # Second request carries a small body so it passes through PhaseBody
  # (bodyless requests complete in scanHeaders and never fire the hook).
  big &= "POST /next HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc"
  doAssert parser.feed(big) == PhaseComplete
  doAssert streamed == 70000, "first body streamed, got " & $streamed
  parser.resetForNext()
  parser.tryAdvance()
  doAssert parser.isComplete(), "pipelined request must parse from leftover"
  doAssert hooks == 2, "hook fires once per request, got " & $hooks
  doAssert parser.peekPath() == "/next"

# ── Server-level: end-to-end transparency ────────────────────────────────────

const PrearmPort = 20181

test "test_server_single_packet_large_raw_streams_to_file":
  const BodySize = 2 * 1024 * 1024
  var expected = newString(BodySize)
  for i in 0 ..< BodySize:
    expected[i] = chr(ord('a') + (i mod 26))
  var handlerOk = false
  var gotStatus = 0
  let loop = newLoop()
  let server = newHttpServer(loop, populate = false)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      if req.streamPath.len > 0 and readFile(req.streamPath) == expected:
        handlerOk = true
        removeFile(req.streamPath)
      res.status(Http200).send("OK")
  server.listen("127.0.0.1", PrearmPort)

  var resp: string = ""
  discard loop.addTimer(50) do (id: int):
    loop.connect("127.0.0.1", PrearmPort,
      onConnect = proc(conn: Connection) =
        # One send: headers + whole 2 MB body (single-packet upload).
        discard conn.send("POST /raw HTTP/1.1\r\nHost: x\r\nContent-Length: " &
                          $BodySize & "\r\nConnection: close\r\n\r\n" & expected)
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        var s = newString(data.len)
        copyMem(addr s[0], unsafeAddr data[0], data.len)
        resp &= s
      ,
      onClose = proc(conn: Connection) =
        server.close()
        loop.stop()
    )
  discard loop.addTimer(10000) do (id: int):
    server.close()
    loop.stop()
  loop.run()
  loop.close()
  doAssert handlerOk, "2MB single-packet body must stream to file byte-identical"
  doAssert "200" in resp, "expected 200, got: " & resp[0 ..< min(60, resp.len)]

test "test_server_single_packet_large_multipart_streams":
  let boundary = "PrearmBoundary"
  let fileContent = repeat('Z', 200 * 1024)  # 200 KB part
  let body = "--" & boundary & "\r\n" &
             "Content-Disposition: form-data; name=\"file\"; filename=\"big.bin\"\r\n" &
             "Content-Type: application/octet-stream\r\n\r\n" &
             fileContent & "\r\n" &
             "--" & boundary & "--\r\n"
  var handlerOk = false
  let loop = newLoop()
  let server = newHttpServer(loop, populate = false)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      let mp = req.getMultipart()
      if mp != nil and req.streamer != nil and mp.isComplete():
        for b in mp:
          if b.dataType == MultipartFile and b.fileName == "big.bin" and
             b.fileSize == fileContent.len and readFile(b.filePath) == fileContent:
            handlerOk = true
        mp.cleanup()
      res.status(Http200).send("OK")
  server.listen("127.0.0.1", PrearmPort + 1)

  var resp: string = ""
  discard loop.addTimer(50) do (id: int):
    loop.connect("127.0.0.1", PrearmPort + 1,
      onConnect = proc(conn: Connection) =
        discard conn.send("POST /up HTTP/1.1\r\nHost: x\r\n" &
                          "Content-Type: multipart/form-data; boundary=" & boundary & "\r\n" &
                          "Content-Length: " & $body.len & "\r\nConnection: close\r\n\r\n" & body)
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        var s = newString(data.len)
        copyMem(addr s[0], unsafeAddr data[0], data.len)
        resp &= s
      ,
      onClose = proc(conn: Connection) =
        server.close()
        loop.stop()
    )
  discard loop.addTimer(10000) do (id: int):
    server.close()
    loop.stop()
  loop.run()
  loop.close()
  doAssert handlerOk, "200KB single-packet multipart must stream with intact file part"
  doAssert "200" in resp

test "test_server_large_chunked_spills_to_file":
  const ChunkCount = 20
  const ChunkSize = 10 * 1024
  var expected = newString(ChunkCount * ChunkSize)
  for i in 0 ..< expected.len:
    expected[i] = chr(ord('0') + (i mod 10))
  var handlerOk = false
  let loop = newLoop()
  let server = newHttpServer(loop, populate = false)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      if req.streamPath.len > 0 and readFile(req.streamPath) == expected:
        handlerOk = true
        removeFile(req.streamPath)
      res.status(Http200).send("OK")
  server.listen("127.0.0.1", PrearmPort + 2)

  var resp: string = ""
  discard loop.addTimer(50) do (id: int):
    loop.connect("127.0.0.1", PrearmPort + 2,
      onConnect = proc(conn: Connection) =
        var raw = "POST /ch HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        for c in 0 ..< ChunkCount:
          raw &= "2800\r\n" & expected[c * ChunkSize ..< (c + 1) * ChunkSize] & "\r\n"
        raw &= "0\r\n\r\n"
        discard conn.send(raw)
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        var s = newString(data.len)
        copyMem(addr s[0], unsafeAddr data[0], data.len)
        resp &= s
      ,
      onClose = proc(conn: Connection) =
        server.close()
        loop.stop()
    )
  discard loop.addTimer(10000) do (id: int):
    server.close()
    loop.stop()
  loop.run()
  loop.close()
  doAssert handlerOk, "200KB chunked upload must spill to file byte-identical"
  doAssert "200" in resp

test "test_server_small_body_fast_path_unchanged":
  # Small bodies stay buffered: getBodyString works, no temp file involved.
  var handlerOk = false
  let loop = newLoop()
  let server = newHttpServer(loop, populate = false)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      if req.getBodyString() == "tiny" and req.streamPath.len == 0 and
         req.streamer == nil:
        handlerOk = true
      res.status(Http200).send("OK")
  server.listen("127.0.0.1", PrearmPort + 3)

  var resp: string = ""
  discard loop.addTimer(50) do (id: int):
    loop.connect("127.0.0.1", PrearmPort + 3,
      onConnect = proc(conn: Connection) =
        discard conn.send("POST /s HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntiny")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        var s = newString(data.len)
        copyMem(addr s[0], unsafeAddr data[0], data.len)
        resp &= s
      ,
      onClose = proc(conn: Connection) =
        server.close()
        loop.stop()
    )
  discard loop.addTimer(10000) do (id: int):
    server.close()
    loop.stop()
  loop.run()
  loop.close()
  doAssert handlerOk, "small buffered fast path must be unchanged"
  doAssert "200" in resp

test "test_server_over_limit_single_packet_413":
  # Oversize body arriving in one packet is still rejected (413 at headers).
  var got413 = false
  let loop = newLoop()
  let server = newHttpServer(loop, populate = false)
  server.maxBodySize = 1024
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http200).send("SHOULD NOT HAPPEN")
  server.listen("127.0.0.1", PrearmPort + 4)

  var resp: string = ""
  discard loop.addTimer(50) do (id: int):
    loop.connect("127.0.0.1", PrearmPort + 4,
      onConnect = proc(conn: Connection) =
        discard conn.send("POST /big HTTP/1.1\r\nHost: x\r\nContent-Length: 65536\r\nConnection: close\r\n\r\n" &
                          repeat('X', 65536))
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        var s = newString(data.len)
        copyMem(addr s[0], unsafeAddr data[0], data.len)
        resp &= s
      ,
      onClose = proc(conn: Connection) =
        server.close()
        loop.stop()
    )
  discard loop.addTimer(10000) do (id: int):
    server.close()
    loop.stop()
  loop.run()
  loop.close()
  doAssert "413" in resp, "expected 413, got: " & resp[0 ..< min(60, resp.len)]

# ── Memory reuse: slab stability, no RSS growth ─────────────────────────────

test "test_streamed_slab_reused_across_requests":
  # Ten large streamed uploads through one parser: the buffer slab must be
  # reused as-is (same address, same length) — no per-request regrowth.
  const BodySize = 512 * 1024
  let parser = newHttpParser()
  parser.onHeadersComplete = proc(p: HttpParser) {.closure.} =
    p.onBodyData = proc(data: openArray[byte]; done: bool) {.closure.} =
      discard data.len
  var firstAddr = 0
  var firstLen = 0
  for i in 0 ..< 10:
    var raw = "POST /big HTTP/1.1\r\nHost: x\r\nContent-Length: " & $BodySize & "\r\n\r\n"
    raw.setLen(raw.len + BodySize)
    for j in 0 ..< BodySize:
      raw[raw.len - BodySize + j] = 'C'
    doAssert parser.feed(raw) == PhaseComplete, "iteration " & $i & " must complete"
    doAssert parser.bufLen < 32 * 1024, "buf compacted on iteration " & $i
    doAssert parser.buf.len <= 65536, "slab bounded on iteration " & $i
    let curAddr = cast[int](unsafeAddr parser.buf[0])
    if i == 0:
      firstAddr = curAddr
      firstLen = parser.buf.len
    else:
      doAssert curAddr == firstAddr, "slab address stable (no realloc) on iteration " & $i
      doAssert parser.buf.len == firstLen, "slab length stable on iteration " & $i
    parser.resetForNext()
    parser.tryAdvance()  # no pipelined bytes: stays in PhaseRequestLine

when defined(linux):
  proc testRssKB(): int =
    ## Resident set size of this process in KB (Linux /proc).
    for line in readFile("/proc/self/status").splitLines():
      if line.startsWith("VmRSS:"):
        return parseInt(line.splitWhitespace()[1])
    return 0

  test "test_server_rss_flat_across_repeated_uploads":
    # Six 4 MB uploads (24 MB total through the server, files deleted by the
    # handler): RSS after a warmup upload must stay flat — nothing may
    # accumulate per request (parser slabs, pooled sessions, temp files).
    const BodySize = 4 * 1024 * 1024
    const Uploads = 6
    var chunk = newString(BodySize)
    for i in 0 ..< BodySize:
      chunk[i] = chr(ord('d') + (i mod 20))
    var done = 0
    var baseline = 0
    let loop = newLoop()
    let server = newHttpServer(loop, populate = false)
    server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
      {.gcsafe.}:
        doAssert req.streamPath.len > 0, "large upload must stream to file"
        doAssert readFile(req.streamPath) == chunk, "upload content intact"
        removeFile(req.streamPath)
        res.status(Http200).send("OK")
    server.listen("127.0.0.1", PrearmPort + 5)

    proc uploadOne() =
      loop.connect("127.0.0.1", PrearmPort + 5,
        onConnect = proc(conn: Connection) =
          discard conn.send("POST /raw HTTP/1.1\r\nHost: x\r\nContent-Length: " &
                            $BodySize & "\r\nConnection: close\r\n\r\n" & chunk)
        ,
        onData = proc(conn: Connection, data: openArray[byte]) =
          discard data.len
        ,
        onClose = proc(conn: Connection) =
          inc done
          if done == 1:
            baseline = testRssKB()  # steady state after warmup
            GC_fullCollect()        # don't let GC timing masquerade as growth
            baseline = testRssKB()
          if done < Uploads:
            uploadOne()
          else:
            server.close()
            loop.stop()
      )

    discard loop.addTimer(50) do (id: int):
      uploadOne()
    discard loop.addTimer(60000) do (id: int):
      server.close()
      loop.stop()
    loop.run()
    loop.close()
    doAssert done == Uploads, "all uploads must complete, got " & $done
    let growth = testRssKB() - baseline
    doAssert growth < 6 * 1024,
      "RSS must stay flat across 24 MB of uploads, grew " & $growth & " KB"
