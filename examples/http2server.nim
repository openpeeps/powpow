## examples/http2server.nim — Runnable HTTP/2 server demo.
##
## Serves `h2` over TLS by default using an embedded self-signed certificate,
## so you can open https://localhost:9040/ straight in a browser
## (accept the self-signed warning on first visit). Cleartext h2c is
## still available for curl and non-browser clients.
##
## Run (h2 over TLS, embedded dev cert):
##   nim c -r examples/http2server.nim
##
## Run (h2 over TLS, your own cert):
##   nim c -r examples/http2server.nim --tls cert.pem key.pem
##
## Run (cleartext h2c):
##   nim c -r examples/http2server.nim --h2c
##
## Test (browser):
##   open https://localhost:9040/ and accept the self-signed warning
##
## Test (h2 over TLS):
##   curl -k --http2 https://localhost:9040/hello
##
## Test (h2c prior knowledge):
##   curl --http2-prior-knowledge http://localhost:9040/
##   curl --http2-prior-knowledge http://localhost:9040/hello?name=ada
##   curl --http2-prior-knowledge http://localhost:9040/api/echo -d 'Hello h2!'
##
## Test (h2c upgrade from HTTP/1.1):
##   curl --http2 http://localhost:9040/time

import ../src/powpow
import std/[os, strutils, times]

const Port = 9040

# Self-signed certificate + key for CN=localhost (valid until 2036).
# Same dev pair as examples/tls_server.nim: the SANs cover `localhost`
# and 127.0.0.1, which is what lets browsers offer a click-through
# instead of a hard failure on the self-signed cert.
const H2TestCert = """-----BEGIN CERTIFICATE-----
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

const H2TestKey = """-----BEGIN PRIVATE KEY-----
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

proc writeTlsFiles(): tuple[cert, key: string] =
  let dir = getTempDir() / "powpow-h2-example"
  discard existsOrCreateDir(dir)
  result.cert = dir / "cert.pem"
  result.key = dir / "key.pem"
  writeFile(result.cert, H2TestCert)
  writeFile(result.key, H2TestKey)

# ── Handler ──────────────────────────────────────────────────────────────────

proc handler(req: H2Request, res: H2Response) {.gcsafe.} =
  {.gcsafe.}:
    let meth = req.meth
    # In HTTP/2 `:path` carries the raw origin-form target, query included.
    let qpos = req.path.find('?')
    let path = if qpos < 0: req.path else: req.path[0 ..< qpos]
    let query = if qpos < 0: "" else: req.path[qpos + 1 .. ^1]

  if meth == "GET" and path == "/":
    res.status(200)
      .header("Content-Type", "text/html; charset=utf-8")
      .send("""<!DOCTYPE html>
<html>
<head><title>powpow</title></head>
<body>
  <h1>powpow HTTP/2 server</h1>
  <p>Multiplexed streams over one TCP connection (RFC 7540).</p>
  <ul>
    <li><a href="/hello">GET /hello</a></li>
    <li><a href="/time">GET /time</a></li>
    <li>POST /api/echo — echo body back</li>
  </ul>
</body>
</html>""")

  elif meth == "GET" and path == "/hello":
    var greeting = "Hello, World!"
    for pair in query.split('&'):
      let kv = pair.split('=')
      if kv.len == 2 and kv[0] == "name":
        greeting = "Hello, " & kv[1] & "!"
        break
    res.status(200)
      .header("Content-Type", "text/plain; charset=utf-8")
      .send(greeting)

  elif meth == "GET" and path == "/time":
    res.status(200)
      .header("Content-Type", "text/plain; charset=utf-8")
      .send($now())

  elif meth == "POST" and path == "/api/echo":
    var contentType = "application/octet-stream"
    for (n, v) in req.headers:
      if n == "content-type":
        contentType = v
        break
    res.status(200)
      .header("Content-Type", contentType)
      .send(req.body)

  else:
    res.status(404).send("404 Not Found: " & meth & " " & path)

# ── Start ────────────────────────────────────────────────────────────────────

let loop = newLoop()

when not defined(windows):
  import ../src/powpow/net/tls

var server: H2Server
when defined(windows):
  # TLS is not supported on Windows: cleartext h2c only.
  server = newH2Server(loop, handler)
  echo "powpow HTTP/2 server (h2c) listening on http://localhost:" & $Port
else:
  if paramCount() >= 1 and paramStr(1) == "--h2c":
    server = newH2Server(loop, handler)
    echo "powpow HTTP/2 server (h2c) listening on http://localhost:" & $Port
  else:
    let (certPath, keyPath) =
      if paramCount() == 3 and paramStr(1) == "--tls":
        (paramStr(2), paramStr(3))
      else:
        writeTlsFiles()
    let ctx = newServerTlsContext(certPath, keyPath)
    server = newH2Server(loop, handler, sslCtx = ctx)
    echo "powpow HTTP/2 server (h2 over TLS) listening on https://localhost:" & $Port
    echo "  Open https://localhost:" & $Port & "/ in a browser (accept the self-signed warning)"

echo "  Press Ctrl+C to stop"
server.listen("127.0.0.1", Port)
loop.run()
