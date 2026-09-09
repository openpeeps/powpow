## tests/test_http2_client.nim — H2 client tests (RFC 7540, M4).
##
## `H2ClientConn` multiplexing plus `H2ClientPool` sharing, against
## `H2Server`: sequential and concurrent requests, large bodies both ways,
## server resets, abrupt-close failover, origin pooling, and TLS.

import ../src/powpow
import ../src/powpow/proto/[http2, hpack, http2conn, http2client]
import std/[unittest, os]

var streamsServed = 0

proc clientHandler(req: H2Request, res: H2Response) {.gcsafe.} =
  {.gcsafe.}:
    inc streamsServed
    if req.path == "/reset":
      res.reset()
      return
    res.header("x-path", req.path).send(req.body)

proc runLoop(loop: Loop, srv: H2Server) =
  discard loop.addTimer(15000) do (id: int):
    srv.close()
    loop.stop()
  loop.run()

test "client_get_and_post":
  streamsServed = 0
  let loop = newLoop()
  let srv = newH2Server(loop, clientHandler)
  srv.listen("127.0.0.1", 29940)
  var gotGet, gotPost = false
  connectH2(loop, "127.0.0.1", 29940,
    proc(c: H2ClientConn, err: string) =
      doAssert err == "", err
      c.request("GET", "/one", [], "", proc(resp: H2ClientResponse,
                                            err: string) =
        doAssert err == "", err
        doAssert resp.status == 200
        doAssert resp.body.len == 0
        var path = ""
        for (n, v) in resp.headers:
          if n == "x-path": path = v
        doAssert path == "/one"
        gotGet = true
      )
      var up = newSeq[byte](8192)
      for i in 0 ..< up.len: up[i] = byte(i mod 251)
      c.request("POST", "/echo", [("content-type", "application/octet-stream")],
        up, proc(resp: H2ClientResponse, err: string) =
          doAssert err == "", err
          doAssert resp.status == 200
          doAssert resp.body == up
          gotPost = true
          c.close()
          srv.close()
          loop.stop()
      )
  )
  runLoop(loop, srv)
  check gotGet
  check gotPost
  check streamsServed == 2
  loop.close()

test "client_multiplex_10_on_one_conn":
  streamsServed = 0
  let loop = newLoop()
  let srv = newH2Server(loop, clientHandler)
  srv.listen("127.0.0.1", 29941)
  var done = 0
  var connsUsed = 0
  connectH2(loop, "127.0.0.1", 29941,
    proc(c: H2ClientConn, err: string) =
      doAssert err == "", err
      inc connsUsed
      for i in 0 ..< 10:
        let path = "/m" & $i
        c.request("GET", path, [], "", proc(resp: H2ClientResponse,
                                            err: string) =
          doAssert err == "", err
          doAssert resp.status == 200
          var got = ""
          for (n, v) in resp.headers:
            if n == "x-path": got = v
          doAssert got.len == 3 and got[0] == '/' and got[1] == 'm'
          inc done
          if done == 10:
            c.close()
            srv.close()
            loop.stop()
        )
  )
  runLoop(loop, srv)
  check done == 10
  check connsUsed == 1
  check streamsServed == 10
  loop.close()

test "client_200k_flow_control":
  streamsServed = 0
  let loop = newLoop()
  let srv = newH2Server(loop, clientHandler)
  srv.listen("127.0.0.1", 29942)
  var up = newSeq[byte](200_000)
  for i in 0 ..< up.len: up[i] = byte((i * 7) mod 256)
  var done = false
  connectH2(loop, "127.0.0.1", 29942,
    proc(c: H2ClientConn, err: string) =
      doAssert err == "", err
      c.request("POST", "/big", [], up, proc(resp: H2ClientResponse,
                                              err: string) =
        doAssert err == "", err
        doAssert resp.status == 200
        doAssert resp.body == up
        done = true
        c.close()
        srv.close()
        loop.stop()
      )
  )
  runLoop(loop, srv)
  check done
  loop.close()

test "client_server_reset_then_healthy":
  streamsServed = 0
  let loop = newLoop()
  let srv = newH2Server(loop, clientHandler)
  srv.listen("127.0.0.1", 29943)
  var sawReset = false
  var sawOk = false
  connectH2(loop, "127.0.0.1", 29943,
    proc(c: H2ClientConn, err: string) =
      doAssert err == "", err
      c.request("GET", "/reset", [], "", proc(resp: H2ClientResponse,
                                               err: string) =
        doAssert err == "reset by peer"
        sawReset = true
        c.request("GET", "/alive", [], "", proc(resp: H2ClientResponse,
                                                 err: string) =
          doAssert err == "", err
          doAssert resp.status == 200
          sawOk = true
          c.close()
          srv.close()
          loop.stop()
        )
      )
  )
  runLoop(loop, srv)
  check sawReset
  check sawOk
  loop.close()

test "client_abrupt_close_fails_fast":
  streamsServed = 0
  let loop = newLoop()
  let srv = newH2Server(loop, clientHandler)
  srv.listen("127.0.0.1", 29944)
  var firstOk = false
  var secondErr = ""
  var holder: H2ClientConn
  connectH2(loop, "127.0.0.1", 29944,
    proc(c: H2ClientConn, err: string) =
      doAssert err == "", err
      holder = c
      c.request("GET", "/first", [], "", proc(resp: H2ClientResponse,
                                               err: string) =
        doAssert err == "", err
        firstOk = true
        srv.close()  # abrupt: GOAWAY + TCP close
        holder.request("GET", "/second", [], "",
          proc(resp: H2ClientResponse, err: string) =
            secondErr = err
            loop.stop()
        )
      )
  )
  runLoop(loop, srv)
  check firstOk
  check secondErr != ""
  loop.close()

test "client_inflight_abort_no_hang":
  streamsServed = 0
  let loop = newLoop()
  let srv = newH2Server(loop, clientHandler)
  srv.listen("127.0.0.1", 29945)
  var fired = 0
  connectH2(loop, "127.0.0.1", 29945,
    proc(c: H2ClientConn, err: string) =
      doAssert err == "", err
      for i in 0 ..< 3:
        c.request("GET", "/slow" & $i, [], "",
          proc(resp: H2ClientResponse, err: string) =
            inc fired
            if fired == 3:
              srv.close()
              loop.stop()
        )
      # Kill the connection while all three are in flight.
      c.close()
  )
  runLoop(loop, srv)
  check fired == 3
  loop.close()

test "pool_shares_origin_connections":
  streamsServed = 0
  let loop = newLoop()
  let srv = newH2Server(loop, clientHandler)
  srv.listen("127.0.0.1", 29946)
  let pool = newH2ClientPool(loop, maxPerOrigin = 2)
  var done = 0
  for i in 0 ..< 6:
    let path = "/p" & $i
    pool.request("127.0.0.1", 29946, false, "GET", path, [], "",
      proc(resp: H2ClientResponse, err: string) =
        doAssert err == "", err
        doAssert resp.status == 200
        inc done
        if done == 6:
          pool.close()
          srv.close()
          loop.stop()
    )
  runLoop(loop, srv)
  check done == 6
  check streamsServed == 6
  loop.close()

when not defined(windows):
  const TlsCert = """-----BEGIN CERTIFICATE-----
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

  const TlsKey = """-----BEGIN PRIVATE KEY-----
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

  test "client_tls_h2_request":
    streamsServed = 0
    let dir = getTempDir() / "powpow-h2client-tls"
    discard existsOrCreateDir(dir)
    let cert = dir / "c.pem"
    let key = dir / "k.pem"
    writeFile(cert, TlsCert)
    writeFile(key, TlsKey)
    let serverCtx = newServerTlsContext(cert, key)
    let loop = newLoop()
    let srv = newH2Server(loop, clientHandler, sslCtx = serverCtx)
    srv.listen("127.0.0.1", 29947)
    var done = false
    let clientCtx = newClientTlsContext(verifyPeer = false)
    clientCtx.setAlpnProtocols(["h2"])
    connectH2Tls(loop, "127.0.0.1", 29947, clientCtx,
      proc(c: H2ClientConn, err: string) =
        doAssert err == "", err
        c.request("GET", "/secure", [], "",
          proc(resp: H2ClientResponse, err: string) =
            doAssert err == "", err
            doAssert resp.status == 200
            var path = ""
            for (n, v) in resp.headers:
              if n == "x-path": path = v
            doAssert path == "/secure"
            done = true
            c.close()
            srv.close()
            loop.stop()
        )
    )
    runLoop(loop, srv)
    check done
    loop.close()
