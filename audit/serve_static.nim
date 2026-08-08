## audit/06_serve_static.nim
##
## P1 — serveStatic with the documented urlPrefix (e.g. "/static") must:
##   1. serve legitimate "/static/<file>" requests (pre-fix: 403 — relPath
##      starts with '/');
##   2. NOT serve sibling-prefix paths like "/staticx/<file>" (pre-fix: 200,
##      content leaked from fsRoot/x/...).
##
## Pre-fix statuses: /static/file -> 403 (broken), /staticx/file -> 200 (leak).
## Post-fix: /static/file -> 200, /staticx/file -> 404.

import powpow
import std/[httpcore, strutils, os, unittest]

const
  root = getTempDir() / "pp_audit_static"
  port = 20098

proc serveStaticProbe(prefix, path: string): tuple[status: int; body: string] =
  var responseData: seq[byte] = @[]
  let loop = newLoop()
  let server = newHttpServer(loop)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    {.gcsafe.}:
      if not serveStatic(res, req, prefix, root):
        res.sendError(Http404, "Not Found")
  server.listen("127.0.0.1", port)

  discard loop.addTimer(50) do (id: int):
    loop.connect("127.0.0.1", port,
      onConnect = proc(conn: Connection) =
        discard conn.send("GET " & path & " HTTP/1.1\r\nHost: localhost\r\n\r\n")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        responseData.add(@data)
        conn.close()
      ,
    )
  discard loop.addTimer(1500) do (id: int):
    server.close()
    loop.stop()

  var polls = 0
  while responseData.len == 0 and polls < 20000:
    loop.poll(1)
    inc polls
  server.close()
  loop.close()
  let resp = cast[string](responseData)
  let line = resp.split("\r\n")[0]
  result.status = try: parseInt(line.split(' ')[1]) except: 0
  result.body = if "\r\n\r\n" in resp: resp.split("\r\n\r\n")[^1].strip() else: ""

suite "serveStatic prefix handling":

  setup:
    removeDir(root)
    createDir(root)
    createDir(root / "x")
    writeFile(root / "root.txt", "ROOT-FILE")
    writeFile(root / "x" / "file.txt", "LEAKED")

  test "legitimate file under the prefix is served":
    let (status, body) = serveStaticProbe("/static/", "/static/root.txt")
    check status == 200
    check body == "ROOT-FILE"

  test "sibling-prefix path is rejected":
    let (status, _) = serveStaticProbe("/static/", "/staticx/file.txt")
    check status == 403 or status == 404

  test "documented no-trailing-slash prefix serves legitimate files":
    # urlPrefix="/static" is the docstring example; legitimate requests must work.
    let (status, body) = serveStaticProbe("/static", "/static/root.txt")
    check status == 200
    check body == "ROOT-FILE"

  test "no-trailing-slash prefix still rejects sibling":
    let (status, _) = serveStaticProbe("/static", "/staticx/file.txt")
    check status == 403 or status == 404

  test "path traversal is rejected":
    let (status, _) = serveStaticProbe("/static/", "/static/../root.txt")
    check status == 403 or status == 404
