# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/net/tls.nim — Non-blocking TLS over powpow Connections (OpenSSL).
##
## This module lets you wrap a `Connection` in TLS, both as a server (implicit
## TLS on accept, or an in-place STARTTLS-style upgrade) and as a client
## (immediately after connect). The handshake is driven by the event loop's
## read/write notifications; once `TlsActive`, all reads/writes on the
## connection are transparently encrypted.
##
## TLS is currently only compiled on POSIX platforms (macOS, BSD, Linux).
## On Windows the API is present but every call raises `SslError`.
##
## ```nim
## import powpow
##
## let loop = newLoop()
## let server = newTcpServer(loop,
##   onAccept = proc(conn: Connection) =
##     conn.wrapTls(serverCtx)
##   ,
##   onData = proc(conn: Connection, data: openArray[byte]) =
##     discard conn.send("pong")
##   ,
## )
## server.listen("0.0.0.0", 8443)
## loop.run()
## ```

import ./tcp
import ../types
import ./tlsapi

type
  TlsRole* = enum
    TlsServer, TlsClient

  SslContext* = ref object
    ctx:  SslCtx
    role: TlsRole

  SslError* = object of CatchableError

when not defined(windows):
  proc newServerTlsContext*(certFile, keyFile: string): SslContext =
    ## Creates a server-side TLS context loaded from the given PEM certificate
    ## and private key files. Raises `SslError` on failure.

    let tlsMethod = TLS_server_method()
    if tlsMethod == nil:
      raise newException(SslError, "TLS_server_method() failed")
    let ctx = SSL_CTX_new(tlsMethod)
    if ctx == nil:
      raise newException(SslError, "SSL_CTX_new() failed")

    if SSL_CTX_use_certificate_file(ctx, certFile.cstring, SSL_FILETYPE_PEM) != 1:
      let err = opensslError()
      SSL_CTX_free(ctx)
      raise newException(SslError, "certificate load failed: " & err)
    if SSL_CTX_use_PrivateKey_file(ctx, keyFile.cstring, SSL_FILETYPE_PEM) != 1:
      let err = opensslError()
      SSL_CTX_free(ctx)
      raise newException(SslError, "private key load failed: " & err)
    if SSL_CTX_check_private_key(ctx) != 1:
      let err = opensslError()
      SSL_CTX_free(ctx)
      raise newException(SslError, "certificate/private key mismatch: " & err)

    result = SslContext(ctx: ctx, role: TlsServer)

  proc newClientTlsContext*(verifyPeer = true): SslContext =
    ## Creates a client-side TLS context. With `verifyPeer` (the default) the
    ## peer certificate chain is verified against the system CA store, so
    ## untrusted / self-signed servers are rejected — set it to `false` only
    ## for self-signed or testing servers.
    let tlsMethod = TLS_client_method()
    if tlsMethod == nil:
      raise newException(SslError, "TLS_client_method() failed")
    let ctx = SSL_CTX_new(tlsMethod)
    if ctx == nil:
      raise newException(SslError, "SSL_CTX_new() failed")
    if verifyPeer:
      if SSL_CTX_set_default_verify_paths(ctx) != 1:
        SSL_CTX_free(ctx)
        raise newException(SslError, "SSL_CTX_set_default_verify_paths() failed")
      SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nil)
    else:
      SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nil)
    result = SslContext(ctx: ctx, role: TlsClient)

  proc wrapTls*(conn: Connection, ctx: SslContext, serverName = "") =
    ## Wrap an existing connected `Connection` in TLS and begin a non-blocking
    ## handshake. For a server this is used for implicit TLS (e.g. SMTP 465) or
    ## an in-place STARTTLS upgrade; for a client it must be called from the
    ## connect callback.
    ##
    ## For clients, pass `serverName` (the host that was connected to) to send
    ## SNI and enforce hostname verification — the peer certificate must match
    ## it in addition to the chain.
    ##
    ## The handshake completes asynchronously on the event loop; any data sent
    ## with `conn.send` before it completes is buffered and flushed once TLS is
    ## active.
    if conn.ssl != nil:
      return
    let ssl = SSL_new(ctx.ctx)
    if ssl == nil:
      raise newException(SslError, "SSL_new() failed")
    if SSL_set_fd(ssl, cint(conn.fd)) != 1:
      SSL_free(ssl)
      raise newException(SslError, "SSL_set_fd() failed")
    case ctx.role
    of TlsServer:
      SSL_set_accept_state(ssl)
    of TlsClient:
      SSL_set_connect_state(ssl)
      if serverName.len > 0:
        discard SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, 0,
                         cast[pointer](serverName.cstring))   # SNI
        discard SSL_set1_host(ssl, serverName.cstring)        # hostname check
    conn.ssl = cast[pointer](ssl)
    conn.tlsState = TlsHandshaking
    # Clients must kick the handshake off by writing the ClientHello; servers
    # are driven by their first read event (accept) or STARTTLS upgrade.
    if ctx.role == TlsClient:
      discard conn.driveHandshake()

  proc isTlsActive*(conn: Connection): bool {.inline.} =
    ## True once the connection's TLS handshake has completed.
    conn.tlsState == TlsActive

else:
  proc newServerTlsContext*(certFile, keyFile: string): SslContext =
    raise newException(SslError, "TLS is not supported on Windows")

  proc newClientTlsContext*(verifyPeer = true): SslContext =
    raise newException(SslError, "TLS is not supported on Windows")

  proc wrapTls*(conn: Connection, ctx: SslContext, serverName = "") =
    raise newException(SslError, "TLS is not supported on Windows")

  proc isTlsActive*(conn: Connection): bool {.inline.} = false
