---
title: TLS
description: "OpenSSL TLS for powpow connections: implicit TLS, STARTTLS-style upgrades, and HTTPS via the HTTP server."
keywords: ["powpow", "tls", "ssl", "https", "openssl"]
---

# TLS

`net/tls.nim` adds OpenSSL TLS to powpow `Connection`s. It supports both
**implicit TLS** (TLS from the first byte — HTTPS) and **in-place upgrades**
(STARTTLS-style: a plaintext connection that negotiates TLS mid-stream).
TLS is not available on Windows (`SslError` is raised).

Runnable example: [`examples/tls_server.nim`](../../examples/tls_server.nim).

## Contexts

```nim
# Server: load the certificate chain and private key
let ctx = newServerTlsContext(certFile = "/path/cert.pem",
                              keyFile  = "/path/key.pem")

# Client: verify the peer (default), or disable verification
let clientCtx = newClientTlsContext(verifyPeer = true)
```

`SslError = object of CatchableError` is raised on failure (e.g. missing or
mismatched key).

## Implicit TLS on a connection

`wrapTls` sets up the SSL object on an already-accepted connection. The
handshake is driven non-blockingly by the loop.

```nim
proc onAccept(conn: Connection) =
  wrapTls(conn, serverCtx)            # server role by default

let server = newTcpServer(loop, onData = ..., onAccept = onAccept, ...)
```

`wrapTls(conn, ctx, serverName = "")` — pass `serverName` for client-mode SNI
(TLS client). `isTlsActive(conn): bool` reports whether a connection is in the
TLS state machine.

## TLS on the HTTP server

The HTTP server has a built-in `sslCtx` slot — set it before `start` and every
connection is wrapped automatically (HTTPS):

```nim
let server = newHttpServer(loop)
server.sslCtx = newServerTlsContext("cert.pem", "key.pem")
server.start(handler, Port(9443))
```

See [`examples/tls_server.nim`](../../examples/tls_server.nim) (embedded
self-signed cert) — `curl -k https://localhost:9443/hello`.

## STARTTLS-style upgrade

Because `wrapTls` can be called at any time, you can upgrade an existing
plaintext connection on the fly:

```nim
# inside an onData handler, after the client says STARTTLS:
wrapTls(conn, serverCtx)
```

The connection's `tlsState` transitions `TlsOff` → `TlsHandshaking` →
`TlsActive`; `driveHandshake`/`tlsRead`/`tlsWrite`/`tlsFree` handle the
non-blocking SSL I/O. This is covered by `tests/test_tls.nim`.

## TLS state

```nim
conn.tlsState   # TlsOff | TlsHandshaking | TlsActive
conn.isTlsActive()
```

## Underlying OpenSSL bindings

`net/tlsapi.nim` is a minimal direct-link OpenSSL binding (`-lssl -lcrypto`)
used by `tls.nim`: `SSL_CTX_new`, `SSL_new`, `SSL_do_handshake`, `SSL_read`,
`SSL_write`, `SSL_shutdown`, `SSL_get_error`, `SSL_set1_host`, `opensslError`,
and the associated constants. See [tlsapi API](../api/tlsapi.md).

## API reference

Full signatures: [TLS API](../api/tls.md). Related: [TCP](tcp.md),
[sockets](sockets.md).
