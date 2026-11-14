## tests/test_client_proxy.nim — H1 client proxying (Phase 1B, part 2: B3).
## Plain-http absolute-URI proxying, Proxy-Authorization, CONNECT tunnels
## to https origins, and proxy error paths.

import std/httpcore except HttpMethod
import std/[os, strutils, unittest]
import ../src/powpow

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
  let dir = getTempDir() / "powpow-tls-test"
  discard existsOrCreateDir(dir)
  result.cert = dir / "test-cert.pem"
  result.key = dir / "test-key.pem"
  writeFile(result.cert, TestCert)
  writeFile(result.key, TestKey)

proc writeProxyCert(): tuple[cert, key: string] =
  let dir = getTempDir() / "powpow-proxy-test"
  discard existsOrCreateDir(dir)
  result.cert = dir / "proxy-cert.pem"
  result.key = dir / "proxy-key.pem"
  writeFile(result.cert, TestCert)
  writeFile(result.key, TestKey)

# ── Plain-http proxy: absolute-URI + Proxy-Authorization ───────────

test "proxy_plain_absolute_uri":
  let client = newHttpClient(proxyUrl = "http://127.0.0.1:19890")
  # The "proxy" answers directly, asserting on what it received.
  let proxy = newTcpServer(client.getLoop(),
    onAccept = proc(conn: Connection) = discard,
    onData = proc(conn: Connection, data: openArray[byte]) =
      {.gcsafe.}:
        var line = ""
        for b in data:
          if b == byte('\r'):
            break
          line.add(char(b))
        let body = "target=" & line
        discard conn.send("HTTP/1.1 200 OK\r\nContent-Length: " & $body.len &
          "\r\nConnection: close\r\n\r\n" & body)
        conn.close()
    ,
    onClose = proc(conn: Connection) = discard,
  )
  proxy.listen("127.0.0.1", 19890)

  let r = client.get("http://127.0.0.1:19891/some/path?q=1")
  check r.getStatusCode() == Http200
  check r.getBodyString() == "target=GET http://127.0.0.1:19891/some/path?q=1 HTTP/1.1"

  proxy.close()
  client.close()

test "proxy_basic_auth_forwarded":
  let client = newHttpClient(proxyUrl = "http://user:pass@127.0.0.1:19892")
  let proxy = newTcpServer(client.getLoop(),
    onAccept = proc(conn: Connection) = discard,
    onData = proc(conn: Connection, data: openArray[byte]) =
      {.gcsafe.}:
        var hdr = ""
        for b in data:
          hdr.add(char(b))
        let tag = "Proxy-Authorization: "
        var auth = "missing"
        let at = hdr.find(tag)
        if at >= 0:
          var eol = hdr.find("\r\n", at)
          if eol < 0:
            eol = hdr.len
          auth = hdr[at + tag.len ..< eol]
        let body = "auth=" & auth
        discard conn.send("HTTP/1.1 200 OK\r\nContent-Length: " & $body.len &
          "\r\nConnection: close\r\n\r\n" & body)
        conn.close()
    ,
    onClose = proc(conn: Connection) = discard,
  )
  proxy.listen("127.0.0.1", 19892)

  let r = client.get("http://127.0.0.1:19893/")
  check r.getBodyString() == "auth=Basic dXNlcjpwYXNz"

  proxy.close()
  client.close()

test "proxy_direct_still_works":
  # A client without proxyUrl is unaffected (regression pin for key change).
  let client = newHttpClient()
  let server = newHttpServer(client.getLoop())
  server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
    res.status(Http200).send(req.getPath())
  server.listen("127.0.0.1", 19894)

  check client.get("http://127.0.0.1:19894/origin").getBodyString() == "/origin"

  server.close()
  client.close()

test "proxy_bad_scheme_and_uds_conflict":
  let bad = newHttpClient(proxyUrl = "https://127.0.0.1:1")
  var raised = false
  try:
    discard bad.get("http://127.0.0.1:1/")
  except HttpError:
    raised = true
  check raised
  bad.close()

when not defined(windows):
  test "proxy_uds_conflict":
    let c = newHttpClient(proxyUrl = "http://127.0.0.1:1")
    var raised = false
    try:
      discard c.request(HttpGet, "http://x/", unixSocket = "/tmp/zz.sock")
    except HttpError:
      raised = true
    check raised
    c.close()

# ── CONNECT tunnel to an https origin ─────────────────────

when not defined(windows):
  test "proxy_connect_tunnel":
    let (cert, key) = writeProxyCert()
    let cc = newClientTlsContext(verifyPeer = false)
    let hc = newHttpClient(cc, timeoutMs = 8000,
                           proxyUrl = "http://127.0.0.1:19896")
    let loop = hc.getLoop()
    # Real https origin behind the tunnel.
    let origin = newHttpServer(loop)
    origin.sslCtx = newServerTlsContext(cert, key)
    origin.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
      res.status(Http200).send("secure-origin")
    origin.listen("127.0.0.1", 19895)
    # Minimal CONNECT proxy: handshake, then blind bidirectional pipe.
    var connectLine = ""
    let proxy = newTcpServer(loop,
      onAccept = proc(conn: Connection) = discard,
      onData = proc(conn: Connection, data: openArray[byte]) =
        {.gcsafe.}:
          let peer = cast[Connection](conn.data)
          if peer != nil:
            # Established tunnel: forward verbatim.
            discard peer.send(data.toOpenArray(0, data.high))
            return
          var head = ""
          for b in data:
            head.add(char(b))
          let term = head.find("\r\n\r\n")
          if term < 0:
            return  # split handshake; localhost delivers it whole
          connectLine = head[0 ..< term]
          loop.connect("127.0.0.1", 19895,
            onConnect = proc(up: Connection) =
              conn.data = cast[pointer](up)
              up.data = cast[pointer](conn)
              discard conn.send("HTTP/1.1 200 Connection Established\r\n\r\n")
            ,
            onData = proc(up: Connection, data2: openArray[byte]) =
              {.gcsafe.}:
                let down = cast[Connection](up.data)
                if down != nil:
                  discard down.send(data2.toOpenArray(0, data2.high))
            ,
            onClose = proc(up: Connection) =
              {.gcsafe.}:
                let down = cast[Connection](up.data)
                up.data = nil
                if down != nil:
                  down.data = nil
                  down.close()
          )
      ,
      onClose = proc(conn: Connection) =
        {.gcsafe.}:
          let peer = cast[Connection](conn.data)
          conn.data = nil
          if peer != nil:
            peer.data = nil
            peer.close()
    )
    proxy.listen("127.0.0.1", 19896)

    let r = hc.get("https://127.0.0.1:19895/")
    check r.getStatusCode() == Http200
    check r.getBodyString() == "secure-origin"
    check connectLine == "CONNECT 127.0.0.1:19895 HTTP/1.1\r\nHost: 127.0.0.1:19895"

    proxy.close()
    origin.close()
    hc.close()

  test "proxy_connect_auth_in_tunnel_head":
    # Proxy-Authorization rides the CONNECT head, never the tunneled request.
    let cc = newClientTlsContext(verifyPeer = false)
    let hc = newHttpClient(cc, timeoutMs = 8000,
                           proxyUrl = "http://u:p@127.0.0.1:19898")
    let loop = hc.getLoop()
    var connectHead = ""
    var tunneledHasAuth = false
    let proxy = newTcpServer(loop,
      onAccept = proc(conn: Connection) = discard,
      onData = proc(conn: Connection, data: openArray[byte]) =
        {.gcsafe.}:
          var head = ""
          for b in data:
            head.add(char(b))
          connectHead = head
          # Answer 200, then inspect the (TLS) bytes for a leaked header.
          discard conn.send("HTTP/1.1 200 Connection Established\r\n\r\n")
          if head.find("\r\n\r\n") >= 0:
            let tail = head[head.find("\r\n\r\n") + 4 .. ^1]
            tunneledHasAuth = tail.contains("Proxy-Authorization")
          conn.close()
      ,
      onClose = proc(conn: Connection) = discard,
    )
    proxy.listen("127.0.0.1", 19898)

    var failed = ""
    try:
      # No real TLS origin behind this fake proxy: the handshake must fail
      # AFTER a well-formed CONNECT (proving head placement), not before.
      discard hc.get("https://127.0.0.1:19899/")
    except HttpError as e:
      failed = e.msg
    check failed.len > 0  # tunnel opened, then TLS died: expected here
    check connectHead.startsWith("CONNECT 127.0.0.1:19899 HTTP/1.1\r\n")
    check connectHead.contains("Proxy-Authorization: Basic dTpw\r\n")
    check not tunneledHasAuth

    proxy.close()
    hc.close()
