## examples/dtls_echo.nim — DTLS 1.2 echo server + bundled client.
##
## Demonstrates powpow's DTLS layer (`net/dtls.nim`): one bound UDP socket
## serving encrypted, per-peer sessions with the stateless cookie exchange on
## by default (HelloVerifyRequest round trip), plus a `--client` mode that
## handshakes, pings, and verifies a >MTU payload end to end.
##
## Run (server):
##   nim c -r examples/dtls_echo.nim
##
## Test with the built-in client (another terminal):
##   nim c -r examples/dtls_echo.nim -- --client
##
## Note: DTLS is POSIX-only (like TLS). On Windows this example raises.

import ../src/powpow
import std/[os]

const Host = "127.0.0.1"
const Port = 9012

# Self-signed certificate + key for CN=localhost (same pair as tls_server).
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

proc runServer() =
  # Write the embedded PEMs to a temp dir so the context can load them.
  let dir = getTempDir() / "powpow-dtls-example"
  discard existsOrCreateDir(dir)
  let certPath = dir / "dtls-echo-cert.pem"
  let keyPath = dir / "dtls-echo-key.pem"
  writeFile(certPath, TestCert)
  writeFile(keyPath, TestKey)

  let loop = newLoop()
  let ctx = newServerDtlsContext(certPath, keyPath)
  var srv: DtlsServer

  srv = newDtlsServer(loop, "0.0.0.0", Port, ctx,
    onData = proc(sess: DtlsSession; data: openArray[byte]) =
      echo "← ", sess.peerAddrStr(), " sends ", data.len,
        " bytes  [live sessions: ", srv.sessionCount(), "]"
      discard sess.send(data),
    onHandshakeDone = proc(sess: DtlsSession) =
      echo "🔒 handshake complete with ", sess.peerAddrStr())

  echo "⚡ DTLS echo server listening on 0.0.0.0:" & $Port & " (DTLS 1.2)"
  echo "  Ping it with:  nim c -r examples/dtls_echo.nim -- --client"
  echo "  Press Ctrl+C to stop"
  loop.run()

proc runClient() =
  let loop = newLoop()
  let ctx = newClientDtlsContext(verifyPeer = false)   # self-signed test cert
  var cli: DtlsSession

  # One payload larger than the ~1400-byte link MTU: send() splits it into
  # MTU-sized DTLS messages and the receiver reassembles across onData calls.
  const BigLen = 8192
  var expected: seq[byte]
  for i in 0 ..< BigLen:
    expected.add byte((i * 31 + 7) mod 253)
  var echoed = 0

  proc startHandshake() =
    cli = connectDtls(loop, Host, Port, ctx,
      onData = proc(sess: DtlsSession; data: openArray[byte]) =
        if echoed == 0:
          echo "→ reply: ", $cast[string](@data)
        inc echoed, data.len
        if echoed >= BigLen:
          echo "✓ big-payload round trip verified (", BigLen, " bytes)"
          cli.close()
          loop.stop(),
      onHandshakeDone = proc(sess: DtlsSession) =
        echo "🔒 handshake done with ", Host, ":", Port
        discard sess.send("ping from powpow dtls!")
        discard sess.send(expected))

  discard loop.addTimer(30) do (id: int):
    startHandshake()

  discard loop.addTimer(5000) do (id: int):
    echo "✗ timed out waiting for echoes"
    loop.stop()

  loop.run()

if paramCount() > 0 and paramStr(1) == "--client":
  runClient()
else:
  runServer()
