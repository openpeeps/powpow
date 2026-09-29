## tests/test_tls_file_download.nim — file downloads over userspace TLS.
##
## Regression cover for two fixed defects that combined to deliver 0-byte
## bodies for HTTPS file responses (CI: `ktls_https_file_download` got
## `0 vs 262144 bytes`):
## - `handleClientRead` returned after the first `onData` whenever TLS was
##   active (meant only for STARTTLS upgrades), delivering at most one TLS
##   record per Read event and stalling multi-record responses.
## - `closeAfterDrain` used an RST close for TLS, discarding the kernel
##   send queue (multi-write responses truncated); `sendFile` also
##   advertised `keep-alive` while closing when the dispatcher had set
##   `closeConn` from the client's `Connection: close`.
## Both tests must deliver the exact file bytes over a real TLS connection
## with kTLS disabled (plain `newServerTlsContext`, no `enableKtls`).

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

const FileSize = 256 * 1024

proc writeFixture(tag: string): tuple[cert, key, file: string] =
  let dir = getTempDir() / ("powpow-tlsfile-" & tag)
  discard existsOrCreateDir(dir)
  result.cert = dir / "c.pem"
  result.key = dir / "k.pem"
  result.file = dir / "payload.bin"
  writeFile(result.cert, TestCert)
  writeFile(result.key, TestKey)
  var payload = newSeq[byte](FileSize)
  for i in 0 ..< FileSize:
    payload[i] = byte((i * 31 + 7) and 0xFF)
  writeFile(result.file, cast[string](payload))

proc download(port: int, tag: string,
              serve: proc(req: HttpRequest, res: HttpResponse) {.gcsafe.}): seq[byte] =
  ## Serve one HTTPS download on `port` and return the raw response bytes.
  let (cert, key, _) = writeFixture(tag)
  let serverCtx = newServerTlsContext(cert, key)
  let loop = newLoop()
  let httpServer = newHttpServer(loop)
  httpServer.sslCtx = serverCtx
  httpServer.handler = serve
  httpServer.listen("127.0.0.1", port)

  var body: seq[byte] = @[]
  var done = false
  discard loop.addTimer(50) do (id: int):
    let clientCtx = newClientTlsContext(verifyPeer = false)
    loop.connect("127.0.0.1", port,
      onConnect = proc(conn: Connection) =
        conn.wrapTls(clientCtx)
        discard conn.send("GET /payload HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        body.add(data)
      ,
      onClose = proc(conn: Connection) =
        done = true
        httpServer.close()
        loop.stop()
      ,
    )

  discard loop.addTimer(8000) do (id: int):
    httpServer.close()
    loop.stop()

  loop.run()
  loop.close()
  doAssert done, "TLS download on port " & $port & " never completed"
  result = body

proc checkBody(body: seq[byte], tag: string) =
  let text = cast[string](body)
  let sep = text.find("\r\n\r\n")
  doAssert sep >= 0, tag & ": response has no header/body separator"
  doAssert text.startsWith("HTTP/1.1 200"), tag & ": unexpected status: " &
    text[0 ..< min(15, text.len)]
  let (_, _, file) = writeFixture(tag)
  let want = readFile(file)
  let got = body[(sep + 4) .. ^1]
  doAssert cast[string](got) == want, tag & ": downloaded bytes differ (" &
    $got.len & " vs " & $want.len & " bytes)"

suite "tls file download":
  test "serveFile over userspace TLS":
    let (_, _, file) = writeFixture("serve")
    proc serve(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
      {.gcsafe.}:
        if req.getPath() == "/payload":
          discard serveFile(res, req, file)
        else:
          res.sendError(Http404, "not found")
    checkBody(download(29883, "serve", serve), "serveFile")

  test "sendFile with close over userspace TLS":
    let (_, _, file) = writeFixture("close")
    proc serve(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
      {.gcsafe.}:
        if req.getPath() == "/payload":
          res.sendFile(file, req)
        else:
          res.sendError(Http404, "not found")
    checkBody(download(29884, "close", serve), "sendFile")
