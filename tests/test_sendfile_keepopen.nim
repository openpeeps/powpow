import std/[os]
import ../src/powpow

when defined(posix):
  proc posixOpen(p: string): cint =
    proc c_open(path: cstring; flags: cint): cint {.
      importc: "open", header: "<fcntl.h>".}
    c_open(p.cstring, 0)  # O_RDONLY

  proc isClosedFd(fd: cint): bool =
    proc fcntl(fd: cint; cmd: cint): cint {.
      importc: "fcntl", header: "<fcntl.h>".}
    fcntl(fd, 1) == -1  # F_GETFD

  proc posixClose(fd: cint) =
    proc c_close(fd: cint): cint {.importc: "close", header: "<unistd.h>".}
    discard c_close(fd)

type Ctx = ref object
  received: seq[byte]
  doneFired: bool
  err: string
  fd: cint
  payloadLen: int
  theLoop: Loop

proc main() =
  # Smoke test: sendFile(keepOpen=true) must NOT close the fd, must fire
  # onComplete after the range drains, and the peer must receive exact bytes.
  let path = getTempDir() / "powpow_sendfile_smoke.bin"
  var payload = newSeq[byte](256 * 1024)
  for i in 0 ..< payload.len: payload[i] = byte(i mod 251)
  writeFile(path, payload)

  let ctx = Ctx(payloadLen: payload.len, theLoop: newLoop())

  block:
    let srv = newTcpServer(ctx.theLoop,
      onData = proc(conn: Connection, data: openArray[byte]) {.gcsafe.} =
        for b in data: ctx.received.add(b)
        if ctx.received.len >= ctx.payloadLen:
          ctx.theLoop.stop()
      )
    srv.listen("127.0.0.1", 41991)

    ctx.theLoop.connect("127.0.0.1", 41991,
      onConnect = proc(conn: Connection) {.closure, gcsafe.} =
        ctx.fd = posixOpen(path)
        let ok = conn.sendFile(ctx.fd, 0, int64(ctx.payloadLen), true,
                               proc() {.closure, gcsafe.} = ctx.doneFired = true,
                               proc(m: string) {.closure, gcsafe.} = ctx.err = m)
        if not ok: ctx.err = "sendFile rejected"
      ,
      onData = proc(conn: Connection, data: openArray[byte]) {.gcsafe.} = discard
    )

    # Safety timeout
    discard ctx.theLoop.addTimer(5000) do (id: int) {.closure, gcsafe.}:
      ctx.err = "timeout"
      ctx.theLoop.stop()

    ctx.theLoop.run()
  ctx.theLoop.close()

  when defined(posix):
    doAssert not isClosedFd(ctx.fd), "fd was closed despite keepOpen=true"
    posixClose(ctx.fd)

  doAssert ctx.err == "", "error: " & ctx.err
  doAssert ctx.doneFired, "onComplete never fired"
  doAssert ctx.received == payload,
    "payload mismatch: got " & $ctx.received.len & " of " & $payload.len

  removeFile(path)
  echo "SMOKE OK: bytes=", ctx.received.len, " onComplete=true fdKeptOpen=true"

main()
