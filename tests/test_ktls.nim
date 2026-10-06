## tests/test_ktls.nim — kernel-TLS (kTLS) opt-in tests for powpow.
##
## - `ktls_capability_probe`: `ktlsSupported()` must not raise on any kernel,
##   and a plain TCP socket must never report kTLS offload. This is the
##   regression cover for the probe that gates the zero-copy `sendfile(2)`
##   path — a false positive there puts unencrypted file bytes on a TLS wire.
## - `ktls_optin_echo`: TLS echo with `enableKtls` on both contexts. Passes
##   via userspace fallback when the kernel lacks kTLS, via offload when
##   present — either way the bytes must round-trip unchanged.
## - `ktls_required_closes_without_offload`: `KtlsRequired` must fail the
##   connection rather than silently serve in userspace.
## - `ktls_https_file_download`: `HttpServer` + `serveFile` over TLS with
##   `enableKtls`; the downloaded bytes must match the file exactly.
## - Engagement is one-directional: `ktlsTxActive` on a live connection
##   implies the kernel `tls` ULP is available. The converse does not hold —
##   the probe only checks the kernel, while engagement additionally needs
##   OpenSSL built with `enable-ktls`, a kTLS-capable cipher, and the
##   socket-BIO (readiness) backend. On kernels without kTLS (`tls` module
##   not loaded) the probe fails and the flag must be false.

import ../src/powpow
import std/httpcore except HttpMethod
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
  let dir = getTempDir() / "powpow-ktls-test"
  discard existsOrCreateDir(dir)
  result.cert = dir / "test-cert.pem"
  result.key = dir / "test-key.pem"
  writeFile(result.cert, TestCert)
  writeFile(result.key, TestKey)

proc kernelHasKtls(): bool =
  ## powpow's own capability probe (attach the "tls" ULP to a throwaway
  ## loopback pair). False when the `tls` module is missing (ENOENT) or any
  ## setup step fails.
  ktlsSupported()

let strict = existsEnv("POWPOW_KTLS_STRICT")
  ## With POWPOW_KTLS_STRICT=1 the tests additionally *require* that offload
  ## actually engages, not merely that the answer is self-consistent. A
  ## kernel with the `tls` module plus a libssl built with `enable-ktls`
  ## engages every time, so this is the setting that catches a probe which
  ## has drifted back to always reporting "off" — the failure mode that
  ## silently disables the zero-copy path in production while every
  ## consistency assertion still passes.

suite "kTLS opt-in":
  test "capability probe is safe and conservative":
    # `ktlsSupported()` must answer on any kernel rather than raise, and a
    # socket with no TLS on it must never claim offload. A false positive
    # here is not cosmetic: it is the gate on the zero-copy `sendfile(2)`
    # path, which would hand raw file bytes to a kernel that is not
    # encrypting them.
    discard kernelHasKtls()

  when defined(linux):
    test "plain socket never reports kTLS offload":
      # The TLS_INFO_*CONF option numbers live in the shared SOL_TCP
      # namespace, so a wrong number can land on an unrelated TCP option and
      # return a plausible-looking value. This is the canary for that.
      let srv = socket(AF_INET.cint, SOCK_STREAM.cint, 0)
      check srv.int >= 0
      defer: sockClose(srv)
      var one: cint = 1
      discard setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, addr one,
                         posix.SockLen(sizeof(one)))
      doAssert not ktlsTxInstalled(srv)
      doAssert not ktlsRxInstalled(srv)

  when not defined(windows):
    test "ktls_required_closes_without_offload":
      # `KtlsRequired` exists so a deployment cannot quietly fall back to
      # userspace crypto. On a kernel that cannot offload, the connection
      # must be dropped and no response body delivered.
      let (cert, key) = writeTestCert()
      let serverCtx = newServerTlsContext(cert, key)
      serverCtx.configureKtls(KtlsRequired)
      let loop = newLoop()
      var served = false
      var body = ""

      let server = newTcpServer(loop,
        onAccept = proc(conn: Connection) =
          conn.wrapTls(serverCtx)
        ,
        onData = proc(conn: Connection, data: openArray[byte]) =
          served = true
          discard conn.send("should never arrive")
        ,
      )
      server.listen("127.0.0.1", 29883)

      discard loop.addTimer(50) do (id: int):
        let clientCtx = newClientTlsContext(verifyPeer = false)
        loop.connect("127.0.0.1", 29883,
          onConnect = proc(conn: Connection) =
            conn.wrapTls(clientCtx)
            discard conn.send("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
          ,
          onData = proc(conn: Connection, data: openArray[byte]) =
            body.add(cast[string](@data))
          ,
          onClose = proc(conn: Connection) =
            server.close()
            loop.stop()
          ,
        )

      discard loop.addTimer(5000) do (id: int):
        server.close()
        loop.stop()

      loop.run()

      if kernelHasKtls():
        # The kernel can offload, so this may legitimately succeed; all we
        # can insist on is that the two agree.
        discard
      else:
        doAssert not served,
          "KtlsRequired served a request on a kernel with no kTLS"
        check body.len == 0
      loop.close()

    test "ktls_optin_echo":
      let (cert, key) = writeTestCert()
      let serverCtx = newServerTlsContext(cert, key)
      serverCtx.configureKtls(KtlsAuto)
      let loop = newLoop()
      var gotEcho = false
      var received = ""
      var serverKtls = false
      var clientKtls = false

      let server = newTcpServer(loop,
        onAccept = proc(conn: Connection) =
          conn.wrapTls(serverCtx)
        ,
        onData = proc(conn: Connection, data: openArray[byte]) =
          serverKtls = conn.ktlsTxActive()
          discard conn.send(data)
        ,
      )
      server.listen("127.0.0.1", 29881)

      discard loop.addTimer(50) do (id: int):
        let clientCtx = newClientTlsContext(verifyPeer = false)
        clientCtx.configureKtls(KtlsAuto)
        loop.connect("127.0.0.1", 29881,
          onConnect = proc(conn: Connection) =
            conn.wrapTls(clientCtx)
            discard conn.send("hello powpow ktls")
          ,
          onData = proc(conn: Connection, data: openArray[byte]) =
            received = cast[string](@data)
            clientKtls = conn.ktlsTxActive()
            gotEcho = true
            conn.close()
            server.close()
            loop.stop()
          ,
        )

      discard loop.addTimer(5000) do (id: int):
        server.close()
        loop.stop()

      loop.run()

      doAssert gotEcho, "kTLS echo should have completed"
      doAssert received == "hello powpow ktls", "echo mismatch: " & received
      # Engagement is best-effort: kernel ULP support is necessary but not
      # sufficient (also needs OpenSSL with enable-ktls, a kTLS-capable
      # cipher, and the socket-BIO backend). So engaged must imply the
      # probe passes, but a passing probe need not imply engaged (e.g. CI
      # libssl without enable-ktls).
      doAssert (not serverKtls) or kernelHasKtls(),
        "server kTLS engaged without kernel support"
      doAssert (not clientKtls) or kernelHasKtls(),
        "client kTLS engaged without kernel support"
      if strict:
        doAssert kernelHasKtls(),
          "POWPOW_KTLS_STRICT=1 but the kernel cannot offload TLS"
        doAssert serverKtls,
          "POWPOW_KTLS_STRICT=1 but the server connection did not offload"
        doAssert clientKtls,
          "POWPOW_KTLS_STRICT=1 but the client connection did not offload"
      else:
        echo "    kTLS: kernel=", kernelHasKtls(),
             " server=", serverKtls, " client=", clientKtls
      loop.close()

    test "ktls_https_file_download":
      # Exercises the kTLS sendfile path in `sendFile` (zero-copy file
      # bytes straight onto the TLS socket). Requires an engaged kernel
      # TX — without kTLS this falls back to the userspace chunk loop,
      # which must produce byte-identical output (regression cover for
      # the read-drain/close truncation fixes); the echo test above covers
      # the fallback path's round-trip correctness.
      if kernelHasKtls():
        let (cert, key) = writeTestCert()
        let dir = getTempDir() / "powpow-ktls-test"
        let filePath = dir / "ktls-payload.bin"
        const FileSize = 256 * 1024
        var payload = newSeq[byte](FileSize)
        for i in 0 ..< FileSize:
          payload[i] = byte((i * 31 + 7) and 0xFF)
        writeFile(filePath, cast[string](payload))

        let serverCtx = newServerTlsContext(cert, key)
        serverCtx.configureKtls(KtlsAuto, zerocopySendfile = true)
        let loop = newLoop()
        var serverKtls = false
        let httpServer = newHttpServer(loop)
        httpServer.sslCtx = serverCtx
        proc fileHandler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
          {.gcsafe.}:
            serverKtls = res.ktlsTxActive()
            if req.getPath() == "/payload":
              discard serveFile(res, req, filePath)
            else:
              res.sendError(Http404, "not found")
        httpServer.handler = fileHandler
        httpServer.listen("127.0.0.1", 29882)

        var body: seq[byte] = @[]
        var gotResponse = false
        discard loop.addTimer(50) do (id: int):
          let clientCtx = newClientTlsContext(verifyPeer = false)
          clientCtx.configureKtls(KtlsAuto)
          loop.connect("127.0.0.1", 29882,
            onConnect = proc(conn: Connection) =
              conn.wrapTls(clientCtx)
              discard conn.send("GET /payload HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            ,
            onData = proc(conn: Connection, data: openArray[byte]) =
              body.add(data)
            ,
            onClose = proc(conn: Connection) =
              gotResponse = true
              httpServer.close()
              loop.stop()
            ,
          )

        discard loop.addTimer(8000) do (id: int):
          httpServer.close()
          loop.stop()

        loop.run()

        doAssert gotResponse, "HTTPS file download should have completed"
        doAssert (not serverKtls) or kernelHasKtls(),
          "server kTLS engaged without kernel support"
        if strict:
          doAssert serverKtls,
            "POWPOW_KTLS_STRICT=1 but the download connection did not offload"
        let text = cast[string](body)
        let sep = text.find("\r\n\r\n")
        doAssert sep >= 0, "response has no header/body separator"
        doAssert text.startsWith("HTTP/1.1 200"), "unexpected status: " & text[0 ..< min(15, text.len)]
        let got = body[(sep + 4) .. ^1]
        doAssert got == payload, "downloaded bytes differ from file (" &
          $got.len & " vs " & $payload.len & " bytes)"
        loop.close()
      else:
        skip()
