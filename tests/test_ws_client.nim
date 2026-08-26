## WebSocket client tests: connectWs / upgradeToWs against a real powpow
## WsServer, plus the handshake-rejection path against a plain HttpServer.

import std/[httpcore, unittest]
import ../src/powpow

test "ws_client_echo_roundtrip":
  ## Text + binary echo, then a client-initiated close that the server parses.
  var echoText = ""
  var echoBin = newSeq[byte](0)
  var serverOpened = 0
  var serverClosed = 0
  var serverCloseCode = -1
  var clientOpened = 0
  let loop = newLoop()
  let server = newWsServer(loop)
  server.onOpen do (ws: WsConnection):
    inc serverOpened
  server.onMessage do (ws: WsConnection, kind: WsFrameKind, data: openArray[byte]):
    case kind
    of wsText:
      ws.sendText(cast[string](@data))
    of wsBinary:
      ws.sendBinary(data)
    else:
      discard
  server.onClose do (ws: WsConnection, code: int, reason: string):
    serverCloseCode = code
    inc serverClosed
    loop.stop()
  server.listen("127.0.0.1", 19994)

  discard loop.addTimer(10) do (id: int):
    let ws = connectWs(loop, "127.0.0.1", 19994, "/",
      onOpen = proc(ws: WsConnection) =
        inc clientOpened
        ws.sendText("hello")
        ws.sendBinary([1.byte, 2, 3])
      ,
      onMessage = proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
        case kind
        of wsText:
          echoText = cast[string](@data)
        of wsBinary:
          echoBin = @data
        else:
          discard
        if echoText.len > 0 and echoBin.len > 0:
          ws.closeWs(1000, "done")
      ,
      onClose = proc(ws: WsConnection, code: int, reason: string) =
        discard
      ,
      onError = proc(ws: WsConnection, err: string) =
        loop.stop()
    )
    check ws != nil

  discard loop.addTimer(15_000) do (id: int):
    loop.stop()

  loop.run()
  server.close()
  loop.close()

  check clientOpened == 1
  check serverOpened == 1
  check echoText == "hello"
  check echoBin == @[1.byte, 2, 3]
  check serverClosed == 1
  check serverCloseCode == 1000

test "ws_client_server_initiated_close":
  ## The server closes; the client must observe the close frame and its code.
  var clientClosed = 0
  var clientCloseCode = -1
  var opened = 0
  let loop = newLoop()
  let server = newWsServer(loop)
  server.onMessage do (ws: WsConnection, kind: WsFrameKind, data: openArray[byte]):
    ws.closeWs(1000, "bye")
  server.listen("127.0.0.1", 19993)

  discard loop.addTimer(10) do (id: int):
    discard connectWs(loop, "127.0.0.1", 19993, "/",
      onOpen = proc(ws: WsConnection) =
        inc opened
        ws.sendText("hi")
      ,
      onMessage = proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
        discard
      ,
      onClose = proc(ws: WsConnection, code: int, reason: string) =
        clientCloseCode = code
        inc clientClosed
        loop.stop()
      ,
      onError = proc(ws: WsConnection, err: string) =
        loop.stop()
    )

  discard loop.addTimer(15_000) do (id: int):
    loop.stop()

  loop.run()
  server.close()
  loop.close()

  check opened == 1
  check clientClosed == 1
  check clientCloseCode == 1000

test "ws_client_upgrade_existing_conn":
  ## upgradeToWs over a raw loop.connect, echo round-trip, then client close.
  var got = ""
  var serverClosed = 0
  var opened = 0
  let loop = newLoop()
  let server = newWsServer(loop)
  server.onMessage do (ws: WsConnection, kind: WsFrameKind, data: openArray[byte]):
    ws.sendText("pong")
  server.onClose do (ws: WsConnection, code: int, reason: string):
    inc serverClosed
    loop.stop()
  server.listen("127.0.0.1", 19992)

  discard loop.addTimer(10) do (id: int):
    loop.connect("127.0.0.1", 19992,
      onConnect = proc(conn: Connection) =
        let ws = upgradeToWs(conn, "/", "127.0.0.1",
          onOpen = proc(ws: WsConnection) =
            inc opened
            ws.sendText("hi")
          ,
          onMessage = proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
            got = cast[string](@data)
            ws.closeWs(1000)
          ,
          onClose = proc(ws: WsConnection, code: int, reason: string) =
            discard
          ,
          onError = proc(ws: WsConnection, err: string) =
            loop.stop()
        )
        check ws != nil
      ,
      onData = proc(conn: Connection, data: openArray[byte]) = discard,
      onClose = proc(conn: Connection) = discard
    )

  discard loop.addTimer(15_000) do (id: int):
    loop.stop()

  loop.run()
  server.close()
  loop.close()

  check opened == 1
  check got == "pong"
  check serverClosed == 1

test "ws_client_handshake_reject":
  var errMsg = ""
  let loop = newLoop()
  let server = newHttpServer(loop)
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http404).send("nope")
  server.listen("127.0.0.1", 19991)

  discard loop.addTimer(10) do (id: int):
    let ws = connectWs(loop, "127.0.0.1", 19991, "/",
      onError = proc(ws: WsConnection, err: string) =
        errMsg = err
        loop.stop()
    )
    check ws != nil

  discard loop.addTimer(15_000) do (id: int):
    loop.stop()

  loop.run()
  server.close()
  loop.close()

  check errMsg.len > 0


# ── Extended client suite: TLS, headers, subprotocols, keepalive, reconnect ──

import std/[os, strutils, atomics, typedthreads]
const WsTestCert = """-----BEGIN CERTIFICATE-----
MIIDJTCCAg2gAwIBAgIUQ9SLaN1JcfaYyluaCXKsGhNnIa4wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgwMTE3MzA0OFoXDTM2MDcy
OTE3MzA0OFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAq4ro9mtmVj4qD9CQeHd9hCpIhw8zTO8jaWl/UI9OtTBS
vI2whQXQaZVCs46HG8Rgu6ANG1vq5oByUQdlBgjY43FF7QpBz/e+0XPMscdSduCE
mMQYx2WJ/3Zb3vbMDvphkTHW/tx+VddCUqIIAp/mUKC705Z3lG/pRtOXIOPMrc4t
2NoPrB0kqNAFrAwAPhjFg2Mf+vGdAOxjrU5GSP5Qi3MjlYL4D45PtUiLgTvuuBeE
OZbh7zXWNtZYQXqpzYYog187ATZpuOczAuY7cMfHUoQkWnCTdFveNQbG4m8nAmK1
9zHGnGGgD4jjrs+uPIn6LO5E+zzJvee+VmWJMwdrvwIDAQABo28wbTAdBgNVHQ4E
FgQUw3eKgdg8j4+CzZA2uo8HnPtptbMwHwYDVR0jBBgwFoAUw3eKgdg8j4+CzZA2
uo8HnPtptbMwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SH
BH8AAAEwDQYJKoZIhvcNAQELBQADggEBAIA+6ROUO4b+oAIQaHhxYMs0D2hHwHdI
uCDr62J24k3m4bVI8f8oJx3WD3Fcfn3qrQ71wMN2VUGzthgmMpn2DX2CXij4+srY
bC1Jl1qdIFtKl5qQKCdvYeHmeU0f5LOthHvCE9vNYnV+4dwegsGlXKmGbDjyHoM/
oar62mvSVYJB/DecAtbuHt9TuJsxFdgKVHBp/bcfJRsncj9Li6FMCrui/Vxda1KY
ceSa+lAGb5Wen43pAyTl9MsBqQrCTLRMHnDb6Bu2cJ8A6+2PeqeHG+QzKcCzaJEw
dl/RF6X9UQUNOyY5hNM4p7nrOqNHjrrwEBRIrLeP+VDQguOeIdGC3/k=
-----END CERTIFICATE-----
"""

const WsTestKey = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCriuj2a2ZWPioP
0JB4d32EKkiHDzNM7yNpaX9Qj061MFK8jbCFBdBplUKzjocbxGC7oA0bW+rmgHJR
B2UGCNjjcUXtCkHP977Rc8yxx1J24ISYxBjHZYn/dlve9swO+mGRMdb+3H5V10JS
oggCn+ZQoLvTlneUb+lG05cg48ytzi3Y2g+sHSSo0AWsDAA+GMWDYx/68Z0A7GOt
TkZI/lCLcyOVgvgPjk+1SIuBO+64F4Q5luHvNdY21lhBeqnNhiiDXzsBNmm45zMC
5jtwx8dShCRacJN0W941BsbibycCYrX3McacYaAPiOOuz648ifos7kT7PMm9575W
ZYkzB2u/AgMBAAECggEABVRkB4qaW9yY6Z6Ka+ET2mrb5QJWZDIGhiG7zbtzb71d
cglEQ5Bvg2WanxczCxb6Bb+jw0atpiq1zTRZxwBjCLH+FllxZljlVKmbNvzL4EX6
ff/oYILpm4ZzCprdXSvEo0Jf/SbJmrjSO9ytO15PcBAxCxJg4GZCYlZ0RWvTx08/
Bij1aBRESLGATn2bA5ZA4CIojaVNQ3fyKADfE9PbAOxvjdPpXlE2k3ylRd2vhd8z
UWtHYCqA+GYheLY69Gx6qhy5BwQkHMcZ09mWCWf+xaH5eOB1eeNoJzKJKZQ+Sv/V
ejoOAaqvQVkGlbr4pxCTrs8IE10lyVie4WZctyHxsQKBgQDkH5NHC6AxhJDiqRDI
6BtTFZINYQSET3ShcCP/ZyiQMiv0+vq0v4zWn5hNhN82JVcLqXhl0kt4gwIT0qw3
EvyxT3VZhW65kPtRlCkJieILS320o8f4wfnQzA3jjRuAtSRSoM6wyrqA4gPvzqnM
D6u0Qt6IKJwkrd7POnHGi3KrrwKBgQDAgU84TyRp5S4PFcR7j2nT8a2y+BJSqToz
MIayVRJaDl+o3EVEmpfa8AbFqgQ+lyUnaZe7XDvh6oHpbTr984qQq/8ca09ElhKn
an8EOOiwBoMfdLPqzcOhwQ/PDlL5Zbk0abP1+3mI6OEY/twuPDhN1Bhipey2GW8k
X2pz3d/08QKBgQCp1jg39JfXRfL4TRaJ/QQa3zxVaZ2LQ/x5FJw4Uf0JHdFMGm78
kn+wajFhxULJdRNRQ2K3q9E0b5TkXTyJ5EDtYVLky0qcLSxul/fVeioobpOwIR+I
PCJZKRJOD4giUrowKji3trcTrTFxIFOZ8TDMi9xRUqqtRCVV8xUx1DATUQKBgD7O
cZBHkfPSyBI34eEGS1rQ8QEBGslJWSm2XVv1kYU8R02KgDb/0SenRC5daAEbww12
0ABa+Vad8kC8WJDeUokc9KDLChOweumQP1ybTJ+RoFo08zZaZ8dwe73sSHoCDEjj
a8mHgIGAqWBEVoXnM9+AoWweAnrvFWnij5K6AwWhAoGBAM7ZUnaWa7Y7Cp8zHFZV
07thnzAnt1BNxGwxT+e+DtThKQgn7GvPdIIoMI6dapHQc7gvq7yCbd7jIlqMGxht
Ej96vuq5B7s7RGFqwt0VkSC5JDAGMKFSj5pAzsgM/+hxW/TbcKeYPxknUdsPkcFA
K41fk5DdTExX/C2iR5wWzVbN
-----END PRIVATE KEY-----
"""

proc writeWsTestCert(): tuple[cert, key: string] =
  let dir = getTempDir() / "powpow-wss-test"
  discard existsOrCreateDir(dir)
  result.cert = dir / "cert.pem"
  result.key = dir / "key.pem"
  writeFile(result.cert, WsTestCert)
  writeFile(result.key, WsTestKey)

when not defined(windows):
  test "ws_client_wss_echo_roundtrip":
    ## connectWs over TLS against an HTTPS server upgrading /ws.
    var echoText = ""
    var opened = 0
    let loop = newLoop()
    let (cert, key) = writeWsTestCert()
    let server = newHttpServer(loop)
    server.sslCtx = newServerTlsContext(cert, key)
    server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
      if req.getPath() == "/ws":
        discard websocketUpgrade(res, req,
          onMessage = proc(ws: WsConnection, kind: WsFrameKind,
                           data: openArray[byte]) =
            if kind == wsText:
              ws.sendText(cast[string](@data)))
      else:
        res.status(Http404).send("nope")
    server.listen("127.0.0.1", 19990)

    discard loop.addTimer(20) do (id: int):
      let ctx = newClientTlsContext(verifyPeer = false)
      let ws = connectWs(loop, "127.0.0.1", 19990, "/ws", "127.0.0.1",
        onOpen = proc(ws: WsConnection) =
          inc opened
          ws.sendText("secure hello")
        ,
        onMessage = proc(ws: WsConnection, kind: WsFrameKind,
                         data: openArray[byte]) =
          echoText = cast[string](@data)
          ws.closeWs(1000, "done")
        ,
        onClose = proc(ws: WsConnection, code: int, reason: string) =
          loop.stop()
        ,
        onError = proc(ws: WsConnection, err: string) =
          echo "wss error: ", err
          loop.stop(),
        tlsCtx = ctx)
      check ws != nil

    discard loop.addTimer(15_000) do (id: int):
      loop.stop()
    loop.run()
    server.close()
    loop.close()
    check opened == 1
    check echoText == "secure hello"

  test "ws_client_headers_and_subprotocol":
    ## Custom headers reach the route handler; subprotocol negotiation picks
    ## the first client-offered protocol the server supports.
    var authSeen = ""
    var negotiated = ""
    var echoed = false
    let loop = newLoop()
    let server = newHttpServer(loop)
    server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
      {.cast(gcsafe).}:
        let hdrs = req.getHeaders()
        # HttpHeaderValues converts to its first value as a string
        authSeen = string(hdrs.getOrDefault("Authorization"))
        if authSeen != "Bearer tok123":
          res.status(Http403).send("forbidden")
          return
      discard websocketUpgrade(res, req,
        protocols = ["chat.v1", "chat.v2"],
        onMessage = proc(ws: WsConnection, kind: WsFrameKind,
                         data: openArray[byte]) =
          ws.sendText(cast[string](@data)))
    server.listen("127.0.0.1", 19989)

    discard loop.addTimer(20) do (id: int):
      let ws = connectWs(loop, "127.0.0.1", 19989, "/", "127.0.0.1",
        onOpen = proc(ws: WsConnection) =
          negotiated = ws.getProtocol()
          check negotiated == "chat.v2"
          ws.sendMessage("ping-proto")
        ,
        onMessage = proc(ws: WsConnection, kind: WsFrameKind,
                         data: openArray[byte]) =
          if kind == wsText and cast[string](@data) == "ping-proto":
            echoed = true
            ws.closeWs(1000, "done")
        ,
        onClose = proc(ws: WsConnection, code: int, reason: string) =
          loop.stop()
        ,
        onError = proc(ws: WsConnection, err: string) =
          echo "hdr/proto error: ", err
          loop.stop(),
        extraHeaders = [("Authorization", "Bearer tok123")],
        protocols = ["chat.v0", "chat.v2"])
      check ws != nil

    discard loop.addTimer(15_000) do (id: int):
      loop.stop()
    loop.run()
    server.close()
    loop.close()
    check authSeen == "Bearer tok123"
    check negotiated == "chat.v2"
    check echoed

  test "ws_client_idle_timeout":
    ## A silent server triggers the client idle timeout with code 1001.
    var closeCode = -1
    let loop = newLoop()
    let server = newWsServer(loop)
    server.listen("127.0.0.1", 19988)

    discard loop.addTimer(20) do (id: int):
      discard connectWs(loop, "127.0.0.1", 19988, "/",
        onOpen = proc(ws: WsConnection) = discard
        ,
        onClose = proc(ws: WsConnection, code: int, reason: string) =
          closeCode = code
          loop.stop()
        ,
        onError = proc(ws: WsConnection, err: string) =
          loop.stop(),
        idleTimeoutMs = 300)

    discard loop.addTimer(15_000) do (id: int):
      loop.stop()
    loop.run()
    server.close()
    loop.close()
    # 1001 when the close frame lands, 1006 when only the FIN races through
    check closeCode == 1001 or closeCode == 1006

test "ws_client_reconnect_gives_up":
  ## Exhausting maxRetries fires onRetry per attempt then onGiveUp, and
  ## run() returns.
  var retries = 0
  var gaveUpWith = -1
  let client = newWsClient(WsReconnectPolicy(
    maxRetries: 3, backoffStartMs: 25, backoffMaxMs: 100, jitter: 0))
  client.onRetry do (attempt: int, delayMs: int):
    inc retries
  client.onGiveUp do (attempts: int):
    gaveUpWith = attempts
  check client.connect("ws://127.0.0.1:19987/", pingIntervalMs = 0) == true
  client.run()
  check retries == 3
  check gaveUpWith == 4
  check client.attemptCount() == 4
const HelperPort = 19985

type HelperCmds = object
  cmd: Atomic[int]     # 0 none | 1 start | 2 kill | 3 restart | 9 exit

proc helperThread(cmds: ptr HelperCmds) {.thread.} =
  {.cast(gcsafe).}:
    let loop = newLoop()
    var srv: WsServer = nil
    var running = true
    while running:
      case cmds[].cmd.load
      of 1, 3:
        if srv == nil:
          srv = newWsServer(loop)
          srv.onMessage do (ws: WsConnection, kind: WsFrameKind,
                            data: openArray[byte]):
            if kind == wsText:
              ws.sendText("srv:" & cast[string](@data))
          srv.listen("127.0.0.1", HelperPort)
        cmds[].cmd.store(0)
      of 2:
        if srv != nil:
          srv.close()
          srv = nil
        cmds[].cmd.store(0)
      of 9:
        running = false
      else:
        discard
      loop.poll(10)
    if srv != nil:
      srv.close()
    loop.close()


test "ws_client_reconnect_recovers":
  ## Server appears late, dies mid-session; the client reconnects through
  ## both failures and completes a round trip on session two.
  var opens = 0
  var retryCount = 0
  var gotReply = ""
  let cmds = createShared(HelperCmds, 1)
  cmds[].cmd.store(0)
  var th: Thread[ptr HelperCmds]
  th.createThread(helperThread, cmds)

  let client = newWsClient(WsReconnectPolicy(
    maxRetries: -1, backoffStartMs: 120, backoffMaxMs: 500, jitter: 0))
  client.onOpen do (ws: WsConnection):
    inc opens
    if opens == 1:
      cmds[].cmd.store(2)          # kill the server mid-session
    else:
      ws.sendMessage("round-two")
  client.onMessage do (ws: WsConnection, kind: WsFrameKind,
                       data: openArray[byte]):
    gotReply = cast[string](@data)
    client.close(1000, "done")
  client.onClose do (ws: WsConnection, code: int, reason: string):
    if code != 1006 and opens == 1:
      echo "unexpected clean close: ", code, " ", reason
  client.onRetry do (attempt: int, delayMs: int):
    inc retryCount
    # Both the first dial (port dead) and every post-drop retry share
    # consecFails==1, so this also restarts the server after each drop.
    cmds[].cmd.store(1)

  check client.connect("ws://127.0.0.1:" & $HelperPort & "/") == true

  # Watchdog: cap the whole run at ~15s; exits early once flagged.
  var done: Atomic[bool]
  done.store(false)
  proc wd(args: tuple[a: ptr WsClient, b: ptr Atomic[bool]]) {.thread.} =
    {.cast(gcsafe).}:
      for i in 0 ..< 300:
        if args.b[].load: return
        sleep(50)
      if not args.b[].load:
        args.a[].close(1010, "watchdog")
  var wdt: Thread[tuple[a: ptr WsClient, b: ptr Atomic[bool]]]
  var argwd: tuple[a: ptr WsClient, b: ptr Atomic[bool]] = (addr client, addr done)
  wdt.createThread(wd, argwd)

  client.run()
  done.store(true)

  cmds[].cmd.store(9)              # tell the helper to exit
  joinThreads(th)
  joinThreads(wdt)

  check opens == 2
  check retryCount >= 2
  check gotReply == "srv:round-two"

test "parse_ws_url_validity":
  let a = parseWsUrl("wss://example.com")
  check a.host == "example.com"
  check a.port == 443
  check a.path == "/"
  check a.tls
  let b = parseWsUrl("WS://a.b:8080/x?y=1")
  check b.host == "a.b"
  check b.port == 8080
  check b.path == "/x?y=1"
  check not b.tls
  let c = parseWsUrl("ws://user:pw@host.io:81/p")
  check c.host == "host.io"
  check c.port == 81
  check c.path == "/p"
  let d = parseWsUrl("ws://[::1]:9000/ws")
  check d.host == "::1"
  check d.port == 9000
  check d.path == "/ws"
  let e = parseWsUrl("ws://plain/v6")
  check e.host == "plain"
  check e.port == 80
  expect WsError:
    discard parseWsUrl("http://nope.example")
  expect WsError:
    discard parseWsUrl("ws://")
  expect WsError:
    discard parseWsUrl("wss://host:notaport/")

when not defined(windows):
  const E2ePort = 19986

  type E2eCmds = object
    cmd: Atomic[int]     # 1 start | 9 exit

  proc e2eThread(cmds: ptr E2eCmds) {.thread.} =
    {.cast(gcsafe).}:
      let loop = newLoop()
      var srv: WsServer = nil
      var running = true
      while running:
        case cmds[].cmd.load
        of 1:
          if srv == nil:
            srv = newWsServer(loop)
            srv.onMessage do (ws: WsConnection, kind: WsFrameKind,
                              data: openArray[byte]):
              case kind
              of wsText:
                ws.sendText(cast[string](@data))
              of wsBinary:
                ws.sendBinary(data)
              else:
                discard
            srv.listen("127.0.0.1", E2ePort)
          cmds[].cmd.store(0)
        of 9:
          running = false
        else:
          discard
        loop.poll(10)
      if srv != nil:
        srv.close()
      loop.close()

  
test "ws_client_highlevel_sendmessage_e2e":
    ## newWsClient end to end: sendMessage dispatches string->text and
    ## seq[byte]->binary; close() unblocks run().
    var kinds: array[2, WsFrameKind]
    var payloadOk = 0
    let cmds = createShared(E2eCmds, 1)
    cmds[].cmd.store(1)
    var th: Thread[ptr E2eCmds]
    th.createThread(e2eThread, cmds)
    sleep(150)                       # give the helper time to bind

    let client = newWsClient()
    client.onOpen do (ws: WsConnection):
      ws.sendMessage("text-please")
      ws.sendMessage(@[9.byte, 8, 7])
    client.onMessage do (ws: WsConnection, kind: WsFrameKind,
                         data: openArray[byte]):
      case kind
      of wsText:
        kinds[0] = kind
        if cast[string](@data) == "text-please": inc payloadOk
      of wsBinary:
        kinds[1] = kind
        if @data == @[9.byte, 8, 7]: inc payloadOk
      else:
        discard
      if payloadOk == 2:
        client.close(1000, "done")

    check client.connect("127.0.0.1", E2ePort) == true
    check client.isConnected() == false   # not yet: run() starts everything

    var done: Atomic[bool]
    done.store(false)
    proc watchdog3(args: tuple[a: ptr WsClient,
                              b: ptr Atomic[bool]]) {.thread.} =
      {.cast(gcsafe).}:
        for i in 0 ..< 300:
          if args.b[].load: return
          sleep(50)
        if not args.b[].load:
          args.a[].close(1010, "watchdog")
    var wd: Thread[tuple[a: ptr WsClient, b: ptr Atomic[bool]]]
    var argW: tuple[a: ptr WsClient, b: ptr Atomic[bool]] = (addr client, addr done)
    wd.createThread(watchdog3, argW)

    client.run()

    done.store(true)
    joinThreads(wd)

    cmds[].cmd.store(9)
    joinThreads(th)

    check kinds[0] == wsText
    check kinds[1] == wsBinary
    check payloadOk == 2
    check client.attemptCount() == 1
