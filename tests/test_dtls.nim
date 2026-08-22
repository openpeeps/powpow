## tests/test_dtls.nim — DTLS 1.2 tests for powpow.
##
## Tests: cookie-exchange handshake, echo roundtrip, multi-peer,
## large fragmented payloads, the session cap, handshake-timeout sweep,
## close_notify propagation, and fatal-handshake onError reporting.

##
import ../src/powpow
import std/[unittest, os, strutils]

const TestCert = """-----BEGIN CERTIFICATE-----
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

const TestKey = """-----BEGIN PRIVATE KEY-----
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

proc writeTestCert(): tuple[cert, key: string] =
  let dir = getTempDir() / "powpow-dtls-test"
  discard existsOrCreateDir(dir)
  result.cert = dir / "test-cert.pem"
  result.key = dir / "test-key.pem"
  writeFile(result.cert, TestCert)
  writeFile(result.key, TestKey)

when not defined(windows):
  test "dtls_echo_roundtrip_cookie":
    let (cert, key) = writeTestCert()
    let ctx = newServerDtlsContext(cert, key)   # cookie exchange on by default
    let loop = newLoop()
    var hsDone = 0
    var gotEcho = false
    var echoed = ""
    const Port = 29910

    let srv = newDtlsServer(loop, "127.0.0.1", Port, ctx,
      onData = proc(sess: DtlsSession; data: openArray[byte]) =
        discard sess.send(data),
      onHandshakeDone = proc(sess: DtlsSession) =
        inc hsDone)

    discard loop.addTimer(30) do (id: int):
      let cctx = newClientDtlsContext(verifyPeer = false)
      var cli: DtlsSession
      cli = connectDtls(loop, "127.0.0.1", Port, cctx,
        onData = proc(sess: DtlsSession; data: openArray[byte]) =
          echoed = cast[string](@data)
          gotEcho = true
          cli.close()
          srv.close()
          loop.stop(),
        onHandshakeDone = proc(sess: DtlsSession) =
          discard sess.send("ping dtls"))

    discard loop.addTimer(5000) do (id: int):
      srv.close()
      loop.stop()

    loop.run()

    doAssert gotEcho, "DTLS echo should have completed"
    doAssert hsDone == 1, "server-side handshake callback should fire once"
    doAssert echoed == "ping dtls", "echo mismatch: " & echoed
    loop.close()

  test "dtls_multi_peer":
    let (cert, key) = writeTestCert()
    let ctx = newServerDtlsContext(cert, key)
    let loop = newLoop()
    var hsDone = 0
    var echoes = 0
    const Port = 29911

    let srv = newDtlsServer(loop, "127.0.0.1", Port, ctx,
      onData = proc(sess: DtlsSession; data: openArray[byte]) =
        discard sess.send(data),
      onHandshakeDone = proc(sess: DtlsSession) =
        inc hsDone)

    proc startClient(tag: string) =
      let cctx = newClientDtlsContext(false)
      var cli: DtlsSession
      cli = connectDtls(loop, "127.0.0.1", Port, cctx,
        onData = proc(sess: DtlsSession; data: openArray[byte]) =
          doAssert cast[string](@data) == tag
          inc echoes
          if echoes == 2:
            cli.close()
            srv.close()
            loop.stop(),
        onHandshakeDone = proc(sess: DtlsSession) =
          discard sess.send(tag))

    discard loop.addTimer(30) do (id: int):
      startClient("alpha")
      startClient("beta")

    discard loop.addTimer(5000) do (id: int):
      srv.close()
      loop.stop()

    loop.run()

    doAssert hsDone == 2, "expected two handshakes, got " & $hsDone
    doAssert echoes == 2, "expected two echoes, got " & $echoes
    loop.close()

  test "dtls_large_payload":
    # 50 KiB payload: OpenSSL fragments into MTU-sized records; each record
    # rides its own datagram and the receiver reassembles via SSL_read.
    const PayloadLen = 50 * 1024
    const Port = 29912
    let (cert, key) = writeTestCert()
    let ctx = newServerDtlsContext(cert, key)
    let loop = newLoop()

    var expected: seq[byte]
    for i in 0 ..< PayloadLen:
      expected.add byte((i * 7 + 13) mod 251)

    var serverGot = 0
    let srv = newDtlsServer(loop, "127.0.0.1", Port, ctx,
      onData = proc(sess: DtlsSession; data: openArray[byte]) =
        for i, b in data:
          doAssert b == expected[serverGot + i], "server payload mismatch at " & $(serverGot + i)
        serverGot += data.len
        discard sess.send(data))

    var clientGot = 0
    discard loop.addTimer(30) do (id: int):
      let cctx = newClientDtlsContext(false)
      var cli: DtlsSession
      cli = connectDtls(loop, "127.0.0.1", Port, cctx,
        onData = proc(sess: DtlsSession; data: openArray[byte]) =
          for i, b in data:
            doAssert b == expected[clientGot + i], "client echo mismatch at " & $(clientGot + i)
          clientGot += data.len
          if clientGot >= PayloadLen:
            cli.close()
            srv.close()
            loop.stop(),
        onHandshakeDone = proc(sess: DtlsSession) =
          discard sess.send(expected))

    discard loop.addTimer(15000) do (id: int):
      srv.close()
      loop.stop()

    loop.run()

    doAssert serverGot == PayloadLen, "server got " & $serverGot & "/" & $PayloadLen
    doAssert clientGot == PayloadLen, "client got " & $clientGot & "/" & $PayloadLen
    loop.close()

  test "dtls_cookie_disabled":
    const Port = 29913
    let (cert, key) = writeTestCert()
    let ctx = newServerDtlsContext(cert, key, cookieExchange = false)
    let loop = newLoop()
    var hsDone = 0
    var gotEcho = false

    let srv = newDtlsServer(loop, "127.0.0.1", Port, ctx,
      onData = proc(sess: DtlsSession; data: openArray[byte]) =
        discard sess.send(data),
      onHandshakeDone = proc(sess: DtlsSession) =
        inc hsDone)

    discard loop.addTimer(30) do (id: int):
      let cctx = newClientDtlsContext(false)
      var cli: DtlsSession
      cli = connectDtls(loop, "127.0.0.1", Port, cctx,
        onData = proc(sess: DtlsSession; data: openArray[byte]) =
          gotEcho = true
          cli.close()
          srv.close()
          loop.stop(),
        onHandshakeDone = proc(sess: DtlsSession) =
          discard sess.send("no-cookie"))

    discard loop.addTimer(5000) do (id: int):
      srv.close()
      loop.stop()

    loop.run()

    doAssert gotEcho and hsDone == 1
    loop.close()

  test "dtls_session_cap":
    # maxSessions=1: the second peer's ClientHello must be ignored entirely.
    const Port = 29914
    let (cert, key) = writeTestCert()
    let ctx = newServerDtlsContext(cert, key)
    let loop = newLoop()
    var cfg = defaultDtlsConfig()
    cfg.maxSessions = 1

    var aHs = false
    var bHs = false
    let srv = newDtlsServer(loop, "127.0.0.1", Port, ctx,
      config = cfg,
      onData = proc(sess: DtlsSession; data: openArray[byte]) =
        discard sess.send(data))

    discard loop.addTimer(30) do (id: int):
      block clientA:
        let cctx = newClientDtlsContext(false)
        var cliA: DtlsSession
        cliA = connectDtls(loop, "127.0.0.1", Port, cctx,
          onHandshakeDone = proc(sess: DtlsSession) =
            aHs = true)
      block clientB:
        let cctx = newClientDtlsContext(false)
        var cliB: DtlsSession
        cliB = connectDtls(loop, "127.0.0.1", Port, cctx,
          onHandshakeDone = proc(sess: DtlsSession) =
            bHs = true)

    discard loop.addTimer(1500) do (id: int):
      check aHs == true
      check bHs == false
      check srv.sessionCount() == 1
      srv.close()
      loop.stop()

    loop.run()

    doAssert aHs, "first client should complete its handshake"
    doAssert not bHs, "second client must be rejected at the cap"
    doAssert srv.sessionCount() == 0, "close should drain sessions"
    loop.close()

  test "dtls_handshake_timeout_sweep":
    # A datagram that passes the ClientHello gate but never completes the
    # handshake must be reaped by the sweeper.
    const Port = 29915
    let (cert, key) = writeTestCert()
    let ctx = newServerDtlsContext(cert, key, cookieExchange = false)
    let loop = newLoop()
    var cfg = defaultDtlsConfig(cookieExchange = false)
    cfg.handshakeTimeoutMs = 300
    cfg.sweepIntervalMs = 100

    var closedCount = 0
    let srv = newDtlsServer(loop, "127.0.0.1", Port, ctx,
      config = cfg,
      onData = proc(sess: DtlsSession; data: openArray[byte]) =
        discard)
    srv.onCloseCb = proc(sess: DtlsSession) =
      inc closedCount

    discard loop.addTimer(30) do (id: int):
      # Raw UDP injector: record header claims 200-byte handshake but delivers
      # only msg_type — OpenSSL waits forever for the rest.
      let raw = connectUdp(loop, "127.0.0.1", Port)
      var pkt: array[14, byte]
      pkt[0] = 22'u8          # handshake content type
      pkt[1] = 0xFE'u8        # DTLS 1.2
      pkt[2] = 0xFD'u8
      pkt[11] = 0x00'u8       # length hi
      pkt[12] = 200'u8        # length lo: far more than we ever send
      pkt[13] = 1'u8          # ClientHello msg type
      discard raw.send(pkt)

    discard loop.addTimer(1500) do (id: int):
      check closedCount == 1
      check srv.sessionCount() == 0
      srv.close()
      loop.stop()

    loop.run()

    doAssert closedCount == 1, "stuck handshake should have been swept"
    doAssert srv.sessionCount() == 0
    loop.close()

  test "dtls_close_notify_reaches_peer":
    # The server echoes once and then closes its session. The client must
    # observe the closure via close_notify (SSL_ERROR_ZERO_RETURN) promptly —
    # not hang until the safety timer. Before the drain fix the record died
    # inside the server's write BIO and clients only found out via timeouts.
    const Port = 29916
    let (cert, key) = writeTestCert()
    let ctx = newServerDtlsContext(cert, key)
    let loop = newLoop()

    var srvEchoedAndClosed = false
    var srvClosed = false
    var clientGotEcho = false
    var clientClosed = false
    var timedOut = false

    let srv = newDtlsServer(loop, "127.0.0.1", Port, ctx,
      onData = proc(sess: DtlsSession; data: openArray[byte]) =
        if srvEchoedAndClosed: return
        srvEchoedAndClosed = true
        discard sess.send(data)
        sess.close()                  # server-initiated close_notify
      ,
      onClose = proc(sess: DtlsSession) =
        srvClosed = true)

    discard loop.addTimer(30) do (id: int):
      let cctx = newClientDtlsContext(false)
      var cli: DtlsSession
      cli = connectDtls(loop, "127.0.0.1", Port, cctx,
        onData = proc(sess: DtlsSession; data: openArray[byte]) =
          clientGotEcho = true
          # Deliberately do NOT close here — wait for the peer's close_notify.
        ,
        onHandshakeDone = proc(sess: DtlsSession) =
          discard sess.send("ping"),
        onClose = proc(sess: DtlsSession) =
          clientClosed = true
          srv.close()
          loop.stop())

    discard loop.addTimer(5000) do (id: int):
      timedOut = true
      srv.close()
      loop.stop()

    loop.run()

    doAssert not timedOut, "close_notify from the server should reach the client"
    doAssert clientGotEcho, "echo should have completed before closure"
    doAssert srvEchoedAndClosed and srvClosed, "server session lifecycle broken"
    doAssert clientClosed, "client must observe the server's close_notify"
    loop.close()

  test "dtls_handshake_fatal_onerror":
    # A datagram that parses far enough to fail inside OpenSSL (garbage
    # ClientHello body) must surface as onError(...) followed by onClose,
    # with the session removed from the table — not a silent close.
    const Port = 29917
    let (cert, key) = writeTestCert()
    let ctx = newServerDtlsContext(cert, key, cookieExchange = false)
    let loop = newLoop()
    var cfg = defaultDtlsConfig(cookieExchange = false)

    var errSeen = ""
    var closedCount = 0
    let srv = newDtlsServer(loop, "127.0.0.1", Port, ctx,
      config = cfg,
      onData = proc(sess: DtlsSession; data: openArray[byte]) =
        discard)

    srv.onErrorCb = proc(sess: DtlsSession; msg: string) =
      errSeen = msg
    srv.onCloseCb = proc(sess: DtlsSession) =
      inc closedCount
      loop.stop()

    discard loop.addTimer(30) do (id: int):
      let raw = connectUdp(loop, "127.0.0.1", Port)
      var pkt: array[29, byte]
      pkt[0] = 22'u8            # handshake content type
      pkt[1] = 0xFE'u8          # DTLS 1.2
      pkt[2] = 0xFD'u8
      pkt[11] = 0x00'u8         # record length hi
      pkt[12] = 16'u8           # record length lo (12 hs hdr + 4 body)
      pkt[13] = 1'u8            # ClientHello msg type
      pkt[14] = 0x00'u8; pkt[15] = 0x00'u8; pkt[16] = 4'u8   # msg length 4
      pkt[17] = 0x00'u8; pkt[18] = 0x00'u8                      # message_seq 0
      pkt[19] = 0x00'u8; pkt[20] = 0x00'u8; pkt[21] = 0x00'u8  # frag offset
      pkt[22] = 0x00'u8; pkt[23] = 0x00'u8; pkt[24] = 4'u8   # frag length 4
      pkt[25] = 0xFF'u8; pkt[26] = 0xFF'u8; pkt[27] = 0xFF'u8; pkt[28] = 0xFF'u8
      discard raw.send(pkt)

    discard loop.addTimer(3000) do (id: int):
      srv.close()
      loop.stop()

    loop.run()

    doAssert errSeen.len > 0, "fatal handshake must fire onError"
    doAssert errSeen.contains("DTLS handshake failed"), "unexpected error: " & errSeen
    doAssert closedCount == 1, "onError must be followed by exactly one onClose"
    doAssert srv.sessionCount() == 0, "failed session must leave the table"
    loop.close()
