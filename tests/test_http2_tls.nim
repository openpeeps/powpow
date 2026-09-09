## tests/test_http2_tls.nim — h2 over TLS tests (RFC 7540 §3.3).
##
## Verifies ALPN `h2` negotiation against `H2Server` with `sslCtx` and a
## full request/response round trip, plus the h2-only policy: a peer
## negotiating anything else is closed after the handshake.

import ../src/powpow
import ../src/powpow/proto/[http2, hpack, http2conn]
import std/[unittest, os, tables]

const H2Magic = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

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
  let dir = getTempDir() / "powpow-h2tls-test"
  discard existsOrCreateDir(dir)
  result.cert = dir / "test-cert.pem"
  result.key = dir / "test-key.pem"
  writeFile(result.cert, TestCert)
  writeFile(result.key, TestKey)

proc h2Handler(req: H2Request, res: H2Response) {.gcsafe.} =
  {.gcsafe.}:
    res.header("x-path", req.path).send(req.body)

when not defined(windows):
  test "h2_tls_alpn_h2_roundtrip":
    let (cert, key) = writeTestCert()
    let serverCtx = newServerTlsContext(cert, key)
    let loop = newLoop()
    let srv = newH2Server(loop, h2Handler, sslCtx = serverCtx)
    srv.listen("127.0.0.1", 29930)

    var parser = newH2FrameParser()
    var dec = newHpackContext()
    var gotStatus = ""
    var gotPath = ""
    var gotBody: seq[byte] = @[]
    var clientAlpn = ""
    var done = false

    discard loop.addTimer(50) do (id: int):
      let clientCtx = newClientTlsContext(verifyPeer = false)
      clientCtx.setAlpnProtocols(["h2"])
      loop.connect("127.0.0.1", 29930,
        onConnect = proc(conn: Connection) =
          conn.wrapTls(clientCtx)
          var pre = newSeq[byte](H2Magic.len)
          for i, c in H2Magic: pre[i] = byte(c)
          for b in encodeSettings(newSeq[H2Setting]()): pre.add(b)
          var enc = newHpackContext()
          for b in encodeHeaders(1, enc.encode(@[
            HpackHeader(name: ":method", value: "GET"),
            HpackHeader(name: ":scheme", value: "https"),
            HpackHeader(name: ":path", value: "/tls"),
            HpackHeader(name: ":authority", value: "127.0.0.1")]),
            endStream = true):
            pre.add(b)
          discard conn.send(pre)  # buffered until the handshake completes
        ,
        onData = proc(conn: Connection, data: openArray[byte]) =
          clientAlpn = conn.alpnSelected()
          for f in parser.feed(data):
            case f.rawType
            of 4:
              if (f.flags and H2FlagAck) == 0:
                discard conn.send(encodeSettingsAck())
            of 1:
              for h in dec.decode(f.payload):
                if h.name == ":status": gotStatus = h.value
                if h.name == "x-path": gotPath = h.value
              if (f.flags and H2FlagEndStream) != 0:
                done = true
            of 0:
              for b in f.payload: gotBody.add(b)
              if (f.flags and H2FlagEndStream) != 0:
                done = true
            else: discard
          if done:
            conn.close()
            srv.close()
            loop.stop()
        ,
      )

    discard loop.addTimer(8000) do (id: int):
      srv.close()
      loop.stop()

    loop.run()

    check clientAlpn == "h2"
    check done
    check gotStatus == "200"
    check gotPath == "/tls"
    check gotBody.len == 0
    loop.close()

  test "h2_tls_non_h2_peer_closed":
    let (cert, key) = writeTestCert()
    let serverCtx = newServerTlsContext(cert, key)
    let loop = newLoop()
    let srv = newH2Server(loop, h2Handler, sslCtx = serverCtx)
    srv.listen("127.0.0.1", 29931)

    var closed = false
    var gotData = false

    discard loop.addTimer(50) do (id: int):
      let clientCtx = newClientTlsContext(verifyPeer = false)
      clientCtx.setAlpnProtocols(["http/1.1"])
      loop.connect("127.0.0.1", 29931,
        onConnect = proc(conn: Connection) =
          conn.wrapTls(clientCtx)
          discard conn.send("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        ,
        onData = proc(conn: Connection, data: openArray[byte]) =
          gotData = true
        ,
        onClose = proc(conn: Connection) =
          closed = true
          srv.close()
          loop.stop()
        ,
      )

    discard loop.addTimer(8000) do (id: int):
      srv.close()
      loop.stop()

    loop.run()

    check closed
    check not gotData
    loop.close()
