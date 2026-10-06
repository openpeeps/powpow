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
import ./common
import ../types
import ./tlsapi
import std/tables

type
  TlsRole* = enum
    TlsServer, TlsClient

  SslContext* = ref object
    ctx:  SslCtx
    role: TlsRole
    alpnProtos*: seq[string]
    alpnWire: string
    ktlsMode*: KtlsMode
      ## Requested kernel-TLS policy. Set with `configureKtls`; applied to
      ## every `SSL*` that `wrapTls` creates on a socket-BIO backend, and
      ## ignored on memory-BIO backends (io_uring) where OpenSSL never sees
      ## the fd and so cannot offload.
    ktlsZerocopySendfile*: bool
      ## Additionally set `SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE`. Only
      ## meaningful alongside a `KtlsMode` other than `KtlsOff`.

  SslError* = object of CatchableError

when not defined(windows):
  var alpnProtosByCtx {.global.}: Table[pointer, seq[string]]

  proc alpnSelectCb(ssl: SslPtr; outProto: ptr ptr uint8;
                    outlen: ptr uint8; input: ptr uint8;
                    inlen: cuint; arg: pointer): cint {.cdecl.} =
    ## Server-side ALPN selection: prefer server order, point `out` into the
    ## client's `input` buffer per OpenSSL contract. Returns SSL_TLSEXT_ERR_*
    ## (0 = negotiated, 3 = no overlap, continue without ALPN).
    if ssl == nil or outProto == nil or outlen == nil:
      return SSL_TLSEXT_ERR_NOACK.cint
    let ctxPtr = SSL_get_SSL_CTX(ssl)
    if ctxPtr == nil or not alpnProtosByCtx.hasKey(ctxPtr):
      return SSL_TLSEXT_ERR_NOACK.cint
    let serverProtos = alpnProtosByCtx[ctxPtr]
    if input == nil or inlen == 0:
      return SSL_TLSEXT_ERR_NOACK.cint
    let clientBuf = cast[ptr UncheckedArray[uint8]](input)
    # Walk server preference order; for each, scan the client list.
    for sp in serverProtos:
      var i = 0
      while i < int(inlen):
        let n = int(clientBuf[i])
        inc i
        if n <= 0 or i + n > int(inlen):
          break
        if n == sp.len:
          var match = true
          for k in 0 ..< n:
            if char(clientBuf[i + k]) != sp[k]:
              match = false
              break
          if match:
            outProto[] = cast[ptr uint8](addr clientBuf[i])
            outlen[] = uint8(n)
            return SSL_TLSEXT_ERR_OK.cint
        i += n
    return SSL_TLSEXT_ERR_NOACK.cint

  proc encodeAlpnWire(protos: openArray[string]): string =
    result = ""
    for p in protos:
      if p.len < 1 or p.len > 255:
        raise newException(SslError, "ALPN protocol name must be 1..255 bytes")
      result.add(char(p.len))
      result.add(p)
    if result.len == 0:
      raise newException(SslError, "ALPN protocol list must not be empty")

  proc setAlpnProtocols*(ctx: SslContext, protos: openArray[string]) =
    ## Advertise ALPN protocols (e.g. `["h2", "http/1.1"]`). For servers this
    ## also installs the select callback preferring server order; for clients
    ## the list is applied per-`SSL*` in `wrapTls`.
    when defined(windows):
      raise newException(SslError, "TLS is not supported on Windows")
    else:
      let wire = encodeAlpnWire(protos)
      if SSL_CTX_set_alpn_protos(ctx.ctx, cast[ptr uint8](wire[0].addr),
                                 cuint(wire.len)) != 0:
        raise newException(SslError, "SSL_CTX_set_alpn_protos() failed: " &
          opensslError())
      ctx.alpnProtos = @protos
      ctx.alpnWire = wire
      if ctx.role == TlsServer:
        alpnProtosByCtx[ctx.ctx] = @protos
        discard SSL_CTX_set_alpn_select_cb(ctx.ctx, alpnSelectCb, nil)

  proc configureKtls*(ctx: SslContext, mode: KtlsMode,
                      zerocopySendfile = false) =
    ## Choose how hard this context tries to move the TLS record layer into
    ## the kernel. `wrapTls` then sets `SSL_OP_ENABLE_KTLS` on each new `SSL*`
    ## (plus `SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE` when
    ## `zerocopySendfile` is true).
    ##
    ## - `KtlsOff` — never offload. This is the default.
    ## - `KtlsAuto` — ask for offload and carry on in userspace if it does
    ##   not happen. The TLS handshake is unaffected either way.
    ## - `KtlsRequired` — ask for offload and drop the connection if it does
    ##   not engage. Use this to make a missing `tls` module, a libssl built
    ##   without `enable-ktls`, or an unsupported cipher a loud failure
    ##   instead of a silent, permanently slower deployment.
    ##
    ## Offload additionally needs: the Linux `tls` module loaded (`modprobe
    ## tls`), OpenSSL >= 3.0 built with `enable-ktls`, a kTLS-capable cipher,
    ## and a socket-BIO backend (the epoll/kqueue readiness loop — the
    ## io_uring backend uses memory BIOs and never offloads). Check the
    ## kernel half up front with `ktlsSupported`, and a live connection with
    ## `ktlsTxActive` / `ktlsRxActive`.
    ##
    ## Call before wrapping connections; changing it later only affects
    ## subsequently wrapped connections.
    when defined(windows):
      raise newException(SslError, "TLS is not supported on Windows")
    else:
      ctx.ktlsMode = mode
      ctx.ktlsZerocopySendfile = zerocopySendfile and mode != KtlsOff

  proc enableKtls*(ctx: SslContext, zerocopySendfile = false) =
    ## Opt in to best-effort kTLS offload. Shorthand for
    ## `configureKtls(ctx, KtlsAuto, zerocopySendfile)`.
    ctx.configureKtls(KtlsAuto, zerocopySendfile)

  proc disableKtls*(ctx: SslContext) =
    ## Stop requesting kTLS offload. Connections already wrapped keep the
    ## offload state they negotiated.
    ctx.configureKtls(KtlsOff)

  proc ktlsSupported*(): bool =
    ## True when this kernel can attach the TLS ULP to a TCP socket, i.e.
    ## kTLS offload is at all possible. Always false off Linux.
    ##
    ## Necessary but not sufficient: engagement also needs OpenSSL with
    ## `enable-ktls`, a kTLS-capable cipher, and a socket-BIO backend.
    ## A false result here means the `tls` module is not loaded —
    ## `modprobe tls` (and loading it at boot) fixes it.
    when defined(linux):
      # The ULP can only be attached to an established TCP socket, so probe
      # with a throwaway loopback pair. Cheaper to ask than to guess.
      let srvFd = socket(AF_INET.cint, SOCK_STREAM.cint, 0)
      if srvFd.int < 0: return false
      defer: sockClose(srvFd)

      var one: cint = 1
      discard setsockopt(srvFd, SOL_SOCKET, SO_REUSEADDR, addr one,
                         sizeof(one).SockLen)
      var bindAddr: Sockaddr_in
      bindAddr.sin_family = AF_INET.int.uint8
      bindAddr.sin_port = 0
      bindAddr.sin_addr.s_addr = 0x0100007F'u32   # 127.0.0.1, network order
      if bindSocket(srvFd, cast[ptr SockAddr](addr bindAddr),
                   sizeof(bindAddr).SockLen) < 0:
        return false
      if listen(srvFd, 1) < 0: return false

      var boundAddr: Sockaddr_in
      var boundLen = sizeof(boundAddr).SockLen
      if getsockname(srvFd, cast[ptr SockAddr](addr boundAddr),
                      addr boundLen) < 0: return false

      let cliFd = socket(AF_INET.cint, SOCK_STREAM.cint, 0)
      if cliFd.int < 0: return false
      defer: sockClose(cliFd)
      if connect(cliFd, cast[ptr SockAddr](addr boundAddr),
                  sizeof(boundAddr).SockLen) < 0:
        return false

      let accFd = accept(srvFd, nil, nil)
      if accFd.int < 0: return false
      defer: sockClose(accFd)

      ktlsUlpAttach(cliFd)
    else:
      false

  proc alpnSelected*(conn: Connection): string =
    ## Negotiated ALPN protocol after the handshake, or "" if none.
    ## Safe to call pre-handshake (returns "").
    if conn.ssl == nil:
      return ""
    var data: ptr uint8 = nil
    var dlen: cuint = 0
    SSL_get0_alpn_selected(cast[SslPtr](conn.ssl), addr data, addr dlen)
    if data == nil or dlen == 0:
      return ""
    result = newString(dlen)
    let src = cast[ptr UncheckedArray[uint8]](data)
    for i in 0 ..< int(dlen):
      result[i] = char(src[i])

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
    when iouEnabled:
      # io_uring backend: TLS runs over memory BIOs. Ciphertext from the ring's
      # RECV completions is fed into the read BIO (see io/tcp), and SSL output is
      # drained from the write BIO and sent via SEND ops. No fd binding.
      let rbio = BIO_new(BIO_s_mem())
      let wbio = BIO_new(BIO_s_mem())
      if rbio == nil or wbio == nil:
        SSL_free(ssl)
        raise newException(SslError, "BIO_new() failed")
      SSL_set_bio(ssl, rbio, wbio)
    else:
      if SSL_set_fd(ssl, cint(conn.fd)) != 1:
        SSL_free(ssl)
        raise newException(SslError, "SSL_set_fd() failed")
      if ctx.ktlsMode != KtlsOff:
        # Permit kernel-TLS offload. OpenSSL engages only when the kernel and
        # the negotiated cipher cooperate; otherwise this is a no-op and
        # userspace crypto is used. `SSL_set_options` (not
        # `SSL_ctrl(SSL_CTRL_OPTIONS)`) so the bit-34 zerocopy-sendfile
        # option survives on ILP32 targets.
        var ops = SslOpEnableKtls
        if ctx.ktlsZerocopySendfile:
          ops = ops or SslOpEnableKtlsTxZerocopySendfile
        discard SSL_set_options(ssl, ops)
    if ctx.alpnWire.len > 0 and ctx.role == TlsClient:
      # Per-connection ALPN list; servers advertise via the SSL_CTX instead.
      if SSL_set_alpn_protos(ssl, cast[ptr uint8](ctx.alpnWire[0].addr),
                             cuint(ctx.alpnWire.len)) != 0:
        SSL_free(ssl)
        raise newException(SslError, "SSL_set_alpn_protos() failed")
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
    conn.ktlsMode = ctx.ktlsMode
    conn.ktlsTxFinal = false
    conn.ktlsRxFinal = false
    # Clients must kick the handshake off by writing the ClientHello; servers
    # are driven by their first read event (accept) or STARTTLS upgrade.
    if ctx.role == TlsClient:
      discard conn.driveHandshake()

  proc isTlsActive*(conn: Connection): bool {.inline.} =
    ## True once the connection's TLS handshake has completed.
    conn.tlsState == TlsActive

  proc ktlsTxActive*(conn: Connection): bool =
    ## True when the kernel encrypts this connection's transmit path. This is
    ## what unlocks the zero-copy `sendfile(2)` path: only a kernel-encrypted
    ## socket may be handed raw file bytes, so a false result means file
    ## bodies fall back to a userspace `SSL_write` chunk loop.
    conn.ktlsTxOffloaded()

  proc ktlsRxActive*(conn: Connection): bool =
    ## True when the kernel decrypts this connection's receive path.
    conn.ktlsRxOffloaded()

  proc ktlsActive*(conn: Connection): bool =
    ## True when the kernel terminates TLS on this connection in either
    ## direction. False on memory-BIO backends (io_uring) and off Linux,
    ## which cannot offload at all.
    conn.ktlsTxActive() or conn.ktlsRxActive()

else:
  proc newServerTlsContext*(certFile, keyFile: string): SslContext =
    raise newException(SslError, "TLS is not supported on Windows")

  proc newClientTlsContext*(verifyPeer = true): SslContext =
    raise newException(SslError, "TLS is not supported on Windows")

  proc wrapTls*(conn: Connection, ctx: SslContext, serverName = "") =
    raise newException(SslError, "TLS is not supported on Windows")

  proc setAlpnProtocols*(ctx: SslContext, protos: openArray[string]) =
    raise newException(SslError, "TLS is not supported on Windows")

  proc alpnSelected*(conn: Connection): string = ""

  proc isTlsActive*(conn: Connection): bool {.inline.} = false

  proc configureKtls*(ctx: SslContext, mode: KtlsMode,
                      zerocopySendfile = false) =
    raise newException(SslError, "TLS is not supported on Windows")

  proc enableKtls*(ctx: SslContext, zerocopySendfile = false) =
    raise newException(SslError, "TLS is not supported on Windows")

  proc disableKtls*(ctx: SslContext) =
    raise newException(SslError, "TLS is not supported on Windows")

  proc ktlsSupported*(): bool = false

  proc ktlsActive*(conn: Connection): bool {.inline.} = false

  proc ktlsTxActive*(conn: Connection): bool {.inline.} = false

  proc ktlsRxActive*(conn: Connection): bool {.inline.} = false
