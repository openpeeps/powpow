# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/net/dtls.nim — Non-blocking DTLS 1.2 (RFC 6347) over powpow UDP.
##
## A single bound UDP socket serves many peers; every peer's DTLS state lives
## in a `DtlsSession` keyed by its network address. Handshakes are driven
## through memory BIOs (the pattern proven by the io_uring TLS path), and
## retransmission timers ride the loop's timer wheel via
## `DTLSv1_get_timeout`/`DTLSv1_handle_timeout`.
##
## Servers enable a stateless HelloVerifyRequest cookie exchange by default
## (HMAC-SHA256 over the peer address, per-context random secret) so garbage
## floods cannot allocate handshake crypto state past the session cap.
##
## ```nim
## import powpow
##
## let loop = newLoop()
## let ctx  = newServerDtlsContext("cert.pem", "key.pem")
## let srv  = newDtlsServer(loop, "0.0.0.0", 4433, ctx) do (sess: DtlsSession, data: openArray[byte]):
##   discard sess.send(data)  # echo
##
## loop.run()
## ```
##
## Windows is not supported (matches the TLS module): the API is present but
## every call raises `DtlsError`.

import ../types
import ../loop
import ./tlsapi
import ./udp
import ./common

import std/[tables, strformat, sequtils]

when not defined(windows):
  import std/posix

# ── Types ─────────────────────────────────────────────────────────────────────

type
  DtlsRole* = enum
    DtlsServerRole
    DtlsClientRole

  DtlsSessionState* = enum
    DtlsHandshaking
      ## Handshake (or its cookie round) in flight.
    DtlsActive
      ## Handshake complete; application data may flow.
    DtlsClosed
      ## Session torn down; object kept only until user callbacks return.

  DtlsConfig* = object
    maxSessions*: int            ## Cap on concurrent sessions (default 1024).
    handshakeTimeoutMs*: int     ## Reap handshakes older than this (default 10s).
    idleTimeoutMs*: int          ## Reap active sessions idle this long (default 120s).
    mtu*: int                    ## Link MTU hint for record sizing (default 1400).
    cookieExchange*: bool        ## Server: require HelloVerifyRequest cookie (default true).
    sweepIntervalMs*: int        ## Sweeper period (default 5000ms).

  DtlsContext* = ref object
    ctx:          SslCtx
    role:         DtlsRole
    cookieSecret: array[CookieSecretLen, byte]

  DtlsSession* = ref object
    ssl:          SslPtr
    rbio:         BioPtr
    wbio:         BioPtr
    writeBuf:     seq[byte]                  # undrained ciphertext awaiting sendto
    peer:         Sockaddr_storage
    peerKey:      string                     # sessions-table key
    state:        DtlsSessionState
    createdAtMs:  int64
    lastActivityMs: int64
    retryTimer:   TimerId                    # one-shot DTLSv1_handle_timeout timer
    flushTimer:   TimerId                    # one-shot congestion-retry flush
    server:       DtlsServer
    ownSock:      UdpSocket                  # client sessions own their socket

  DtlsServer* = ref object
    sock:     UdpSocket
    loop:     Loop
    ctx:      DtlsContext
    config:   DtlsConfig
    sessions: Table[string, DtlsSession]
    handshakes*: int                        # count of sessions mid-handshake
    connectedSock: bool                     # client mode: socket is connect()ed
    sweepTimer: TimerId
    onDataCb*:           proc(sess: DtlsSession; data: openArray[byte]) {.closure.}
    onHandshakeDoneCb*:  proc(sess: DtlsSession) {.closure.}
    onCloseCb*:          proc(sess: DtlsSession) {.closure.}
    onErrorCb*:          proc(sess: DtlsSession; msg: string) {.closure.}

  DtlsError* = object of CatchableError

# ── Defaults ──────────────────────────────────────────────────────────────────

const
  DtlsMtuDefault* = 1400
  DtlsMaxChunk* = 1350               ## plaintext per message; record+overhead stays under one MTU
  DtlsMaxSessionsDefault* = 1024
  DtlsHandshakeTimeoutDefaultMs* = 10_000
  DtlsIdleTimeoutDefaultMs* = 120_000
  DtlsSweepIntervalDefaultMs* = 5_000

proc defaultDtlsConfig*(cookieExchange = true): DtlsConfig =
  DtlsConfig(
    maxSessions: DtlsMaxSessionsDefault,
    handshakeTimeoutMs: DtlsHandshakeTimeoutDefaultMs,
    idleTimeoutMs: DtlsIdleTimeoutDefaultMs,
    mtu: DtlsMtuDefault,
    cookieExchange: cookieExchange,
    sweepIntervalMs: DtlsSweepIntervalDefaultMs)

when defined(windows):
  proc newServerDtlsContext*(certFile, keyFile: string;
      cookieExchange = true): DtlsContext =
    raise newException(DtlsError, "DTLS is not supported on Windows")

  proc newClientDtlsContext*(verifyPeer = false): DtlsContext =
    raise newException(DtlsError, "DTLS is not supported on Windows")

else:
  # ══ POSIX implementation ══════════════════════════════════════════════════

  type
    Timeval {.importc: "struct timeval", header: "<sys/time.h>", final.} = object
      tv_sec: clong
      tv_usec: clong

  # ── Address helpers ────────────────────────────────────────────────────────

  proc normPeer(peer: Sockaddr_storage): Sockaddr_storage =
    ## Zero-padded copy keeping only identity fields — family+port+address for
    ## IPv4 (8 bytes), plus flowinfo+address+scope for IPv6 (28 bytes). The
    ## remaining storage padding may be uninitialised stack garbage in callers,
    ## so table keys and cookie HMACs must never see it.
    result = default(Sockaddr_storage)
    let n = if peer.ss_family == AF_INET.cushort: 8 else: 28
    if n <= sizeof(Sockaddr_storage):
      copyMem(addr result, unsafeAddr peer, n)

  proc addrKey(peer: Sockaddr_storage): string =
    ## Stable sessions-table key over the normalized peer bytes.
    let p = normPeer(peer)
    let keyLen = sizeof(p)
    result = newString(keyLen)
    copyMem(addr result[0], unsafeAddr p, keyLen)

  proc peerAddrStr*(sess: DtlsSession): string =
    ## Human-readable `ip:port` of the session peer (IPv4; IPv6 shown compactly).
    let sa = cast[ptr Sockaddr_in6](unsafeAddr sess.peer)
    if sa.sin6_family.cint == AF_INET:
      let v4 = cast[ptr Sockaddr_in](unsafeAddr sess.peer)[]
      let ip = uint32(v4.sin_addr.s_addr)
      let port = (v4.sin_port.uint16 shr 8) or (v4.sin_port.uint16 shl 8)
      &"{ip and 0xFF}.{(ip shr 8) and 0xFF}.{(ip shr 16) and 0xFF}.{(ip shr 24) and 0xFF}:{port}"
    else:
      "(non-ipv4)"

  # ── Stateless cookie (HMAC-SHA256 over the raw sockaddr) ──────────────────

  proc cookieFor(ctx: DtlsContext; peer: Sockaddr_storage;
                 outBuf: ptr UncheckedArray[byte]; outLen: ptr cuint) =
    var mdLen: cuint = 0
    discard HMAC(EVP_sha256(), addr ctx.cookieSecret[0], CookieSecretLen.cint,
                 unsafeAddr peer, sizeof(Sockaddr_storage).cint,
                 outBuf, addr mdLen)
    outLen[] = CookieMacLen.cuint

  proc verifyCookie(ctx: DtlsContext; peer: Sockaddr_storage;
                    cookie: ptr UncheckedArray[byte]; cookieLen: cuint): cint =
    if cookieLen != CookieMacLen.cuint:
      return 0
    const Sha256Len = 32
    var expected {.noInit.}: array[Sha256Len, byte]   # HMAC writes the full digest
    var mdLen: cuint = 0
    discard HMAC(EVP_sha256(), addr ctx.cookieSecret[0], CookieSecretLen.cint,
                 unsafeAddr peer, sizeof(Sockaddr_storage).cint,
                 cast[ptr UncheckedArray[byte]](addr expected[0]), addr mdLen)
    var diff: byte = 0
    for i in 0 ..< CookieMacLen:
      diff = diff or (expected[i] xor cookie[i])
    if diff == 0: 1.cint else: 0.cint

  # ── Cookie callbacks: recover the session via SSL ex_data ─────────────────

  var gExDataIdx = -1.cint

  proc ensureExDataIdx() =
    if gExDataIdx < 0:
      gExDataIdx = CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL,
                                           0, nil, nil, nil, nil)

  proc cookieGenCb(ssl: SslPtr; cookie: ptr UncheckedArray[byte];
                   cookieLen: ptr cuint): cint {.cdecl.} =
    let p = SSL_get_ex_data(ssl, gExDataIdx)
    if p == nil: return 0
    let sess = cast[DtlsSession](p)
    cookieFor(sess.server.ctx, sess.peer, cookie, cookieLen)
    1.cint

  proc cookieVerifyCb(ssl: SslPtr; cookie: ptr UncheckedArray[byte];
                      cookieLen: cuint): cint {.cdecl.} =
    let p = SSL_get_ex_data(ssl, gExDataIdx)
    if p == nil: return 0
    let sess = cast[DtlsSession](p)
    verifyCookie(sess.server.ctx, sess.peer, cookie, cookieLen)

  # ── Session I/O internals ─────────────────────────────────────────────────

  proc drainWriteBio(sess: DtlsSession) {.gcsafe.}
  proc armFlushRetry(sess: DtlsSession) {.gcsafe.}
  proc driveHandshake(sess: DtlsSession) {.gcsafe.}

  proc flushPending(sess: DtlsSession) {.gcsafe.} =
    ## Send queued ciphertext records as individual datagrams. A datagram is
    ## atomic on UDP: either the whole record goes out or it stays queued for
    ## a quick retry (the socket send buffer fills momentarily under bursts).
    const HdrLen = 13
    while sess.writeBuf.len >= HdrLen:
      let recLen = (sess.writeBuf[11].int shl 8) or sess.writeBuf[12].int
      let total = HdrLen + recLen
      if total > sess.writeBuf.len: break        # partial record; wait for more
      let srv = sess.server
      let sent = if srv.connectedSock:
          # Connected sockets reject explicit-address sendto (EISCONN); the
          # kernel already knows the peer.
          srv.sock.send(sess.writeBuf.toOpenArray(0, total - 1))
        else:
          sendTo(srv.sock, sess.writeBuf.toOpenArray(0, total - 1), sess.peer)
      if sent <= 0:
        sess.armFlushRetry()
        return
      let rest = sess.writeBuf.len - total
      if rest > 0:
        copyMem(addr sess.writeBuf[0], addr sess.writeBuf[total], rest)
      sess.writeBuf.setLen(rest)
    if sess.writeBuf.len == 0 and sess.flushTimer != TimerId(0):
      sess.server.loop.cancelTimer(sess.flushTimer)
      sess.flushTimer = TimerId(0)

  proc armFlushRetry(sess: DtlsSession) {.gcsafe.} =
    if sess.flushTimer != TimerId(0): return
    sess.flushTimer = sess.server.loop.addTimer(1) do (id: int):
      sess.flushTimer = TimerId(0)
      if sess.state != DtlsClosed:
        sess.drainWriteBio()

  proc drainWriteBio(sess: DtlsSession) {.gcsafe.} =
    ## Move all pending ciphertext from the write BIO into `writeBuf`, then
    ## flush complete DTLS records as individual datagrams. Records are
    ## self-delimiting: 13-byte header, length in bytes 11..12 (big-endian).
    var tmp: array[4096, byte]
    while true:
      let n = BIO_read(sess.wbio, addr tmp[0], tmp.len.cint)
      if n <= 0: break
      sess.writeBuf.add(tmp.toOpenArray(0, n - 1))
    sess.flushPending()

  proc cancelRetry(sess: DtlsSession) {.gcsafe.} =
    if sess.retryTimer != TimerId(0):
      sess.server.loop.cancelTimer(sess.retryTimer)
      sess.retryTimer = TimerId(0)

  proc armRetryTimer(sess: DtlsSession) {.gcsafe.} =
    ## Ask OpenSSL for the next retransmission deadline and arm a one-shot
    ## timer. Called after every handshake-driving operation.
    var tv: Timeval
    let r = SSL_ctrl(sess.ssl, DTLS_CTRL_GET_TIMEOUT, 0, addr tv)
    cancelRetry(sess)
    if r > 0:
      let delay = clamp(tv.tv_sec.int64 * 1000 + (tv.tv_usec.int64 + 999) div 1000,
                        1, 60_000).int
      sess.retryTimer = sess.server.loop.addTimer(delay) do (id: int):
        sess.retryTimer = TimerId(0)
        if sess.state == DtlsHandshaking and sess.ssl != nil:
          # Retransmit the last flight (HANDLE_TIMEOUT writes it into the
          # write BIO), then re-drive the state machine so an exhausted
          # retransmission budget surfaces its fatal error HERE and closes
          # the session — previously only HANDLE_TIMEOUT ran, the give-up
          # error was never read, and a vanished peer was retried forever.
          discard SSL_ctrl(sess.ssl, DTLS_CTRL_HANDLE_TIMEOUT, 0, nil)
          sess.lastActivityMs = monoMs()
          sess.driveHandshake()

  proc close*(sess: DtlsSession) {.gcsafe.} =
    ## Tear the session down: notify, free OpenSSL state, drop from the table.
    ##
    ## Emits a best-effort close_notify for BOTH roles while the socket is
    ## still open: SSL_shutdown queues the record into the write BIO and
    ## drainWriteBio flushes it as a datagram. (Previously the record was
    ## never drained and clients never shut down at all, so peers only learned
    ## about closure through their sweeper/idle timeout.)
    if sess.state == DtlsClosed: return
    let wasActive = sess.state == DtlsActive
    if sess.state == DtlsHandshaking:
      dec sess.server.handshakes
    sess.state = DtlsClosed
    sess.cancelRetry()
    if sess.flushTimer != TimerId(0):
      sess.server.loop.cancelTimer(sess.flushTimer)
      sess.flushTimer = TimerId(0)
    if sess.ssl != nil:
      if wasActive:
        # Best-effort close_notify for BOTH roles: SSL_shutdown queues the
        # alert into the write BIO and drainWriteBio pushes it out while the
        # socket is still open. (SSL_shutdown returning 0 just means the
        # peer's close_notify has not arrived yet — fire and forget on UDP.)
        discard SSL_shutdown(sess.ssl)
        sess.drainWriteBio()
        # The drain may re-arm the flush retry on EAGAIN; cancel it — this
        # socket is going away regardless.
        if sess.flushTimer != TimerId(0):
          sess.server.loop.cancelTimer(sess.flushTimer)
          sess.flushTimer = TimerId(0)
      SSL_free(sess.ssl)
      sess.ssl = nil
    if sess.ownSock != nil:
      sess.ownSock.close()
      sess.ownSock = nil
    let srv = sess.server
    srv.sessions.del(sess.peerKey)
    if srv.onCloseCb != nil:
      let cb = srv.onCloseCb
      {.cast(gcsafe).}:
        cb(sess)

  proc fail(sess: DtlsSession; msg: string) {.gcsafe.} =
    ## Surface a fatal error to the application, then tear the session down.
    ## The app observes onError(msg) followed by onClose — two callbacks per
    ## fatal. Idempotent: a callback that closes the session re-entrantly
    ## makes the trailing close() a no-op.
    if sess.state == DtlsClosed: return
    let srv = sess.server
    if srv.onErrorCb != nil:
      let cb = srv.onErrorCb
      {.cast(gcsafe).}:
        cb(sess, msg)
    sess.close()

  proc send*(sess: DtlsSession; data: openArray[byte]): int {.gcsafe.} =
    ## Encrypt and transmit application data. Returns plaintext bytes accepted,
    ## 0 while the write side is congested, or -1 on fatal errors.
    ##
    ## Each SSL_write call becomes one DTLS message; OpenSSL caps those at
    ## 16 KiB ("dtls message too big") and — over memory BIOs — does NOT
    ## fragment application data to the link MTU. Oversized records overflow
    ## typical UDP receive buffers and are silently truncated by recvfrom,
    ## deadlocking the record stream. So this proc splits input into
    ## MTU-sized messages itself; the peer's SSL_read reassembles them as an
    ## ordered plaintext stream across onData callbacks.
    if sess.state != DtlsActive:
      return -1
    if data.len == 0:
      return 0
    sess.lastActivityMs = monoMs()
    var sent = 0
    while sent < data.len:
      let take = min(data.len - sent, DtlsMaxChunk)
      let r = SSL_write(sess.ssl, unsafeAddr data[sent], take.cint)
      if r <= 0:
        let e = SSL_get_error(sess.ssl, r)
        if e == SSL_ERROR_WANT_READ or e == SSL_ERROR_WANT_WRITE:
          break                       # congested; caller retries remainder
        let detail = opensslError()
        sess.fail(if detail.len > 0: "DTLS write failed: " & detail
                  else: "DTLS write failed")
        return if sent > 0: sent else: -1
      inc sent, r.int
      sess.drainWriteBio()            # ship each record immediately
    return sent

  proc send*(sess: DtlsSession; data: string): int {.inline.} =
    ## Convenience overload for text payloads.
    if data.len == 0: return 0
    sess.send(data.toOpenArrayByte(0, data.high))

  proc driveHandshake(sess: DtlsSession) {.gcsafe.} =
    ## Progress a non-blocking DTLS handshake over the memory BIO pair.
    if sess.ssl == nil or sess.state != DtlsHandshaking:
      return
    sess.lastActivityMs = monoMs()
    let r = SSL_do_handshake(sess.ssl)
    sess.drainWriteBio()          # ClientHello / flight responses go out here
    if r == 1:
      sess.state = DtlsActive
      dec sess.server.handshakes
      sess.cancelRetry()
      if sess.server.onHandshakeDoneCb != nil:
        let cb = sess.server.onHandshakeDoneCb
        {.cast(gcsafe).}:
          cb(sess)
      return
    let e = SSL_get_error(sess.ssl, r)
    if e == SSL_ERROR_WANT_READ or e == SSL_ERROR_WANT_WRITE:
      sess.armRetryTimer()
    else:
      let detail = opensslError()
      sess.fail(if detail.len > 0: "DTLS handshake failed: " & detail
                else: "DTLS handshake failed")

  proc deliverPlaintext(sess: DtlsSession) {.gcsafe.} =
    ## Drain decrypted application data and hand it to the user callback.
    var outBuf: array[16 * 1024, byte]
    while true:
      # Re-validate every turn: the onData callback may close the session
      # re-entrantly (e.g. an echo handler whose send() fails), which frees
      # sess.ssl — looping into SSL_read(nil) would segfault.
      if sess.ssl == nil or sess.state != DtlsActive:
        return
      let r = SSL_read(sess.ssl, addr outBuf[0], outBuf.len.cint)
      if r <= 0:
        let e = SSL_get_error(sess.ssl, r)
        if e == SSL_ERROR_ZERO_RETURN:
          sess.close()            # clean close_notify from the peer
          return
        if e == SSL_ERROR_WANT_READ or e == SSL_ERROR_WANT_WRITE:
          return                  # whole record not yet available
        let detail = opensslError()
        sess.fail(if detail.len > 0: "DTLS read failed: " & detail
                  else: "DTLS read failed")
        return
      sess.drainWriteBio()        # SSL_read may trigger retransmits/alerts
      if sess.state != DtlsActive: return   # closed by close-notify alert
      if sess.server.onDataCb != nil:
        let cb = sess.server.onDataCb
        {.cast(gcsafe).}:
          cb(sess, outBuf.toOpenArray(0, r - 1))

  proc feedDatagram(sess: DtlsSession; data: openArray[byte]) {.gcsafe.} =
    ## Route one inbound datagram into its session.
    discard BIO_write(sess.rbio, unsafeAddr data[0], data.len.cint)
    case sess.state
    of DtlsHandshaking:
      sess.driveHandshake()
      if sess.state == DtlsActive:
        # A final flight can carry early application data.
        sess.deliverPlaintext()
    of DtlsActive:
      sess.deliverPlaintext()
    of DtlsClosed:
      discard

  # ── Session creation & demux ───────────────────────────────────────────────

  proc looksLikeClientHello(data: openArray[byte]): bool =
    ## DTLS record header is 13 bytes; the handshake message header follows and
    ## starts with msg_type. ClientHello == msg_type 1.
    data.len >= 14 and data[0].uint8 == 22'u8 and data[13].uint8 == 1'u8

  proc createSession(srv: DtlsServer; peer: Sockaddr_storage;
                     ssl: SslPtr): DtlsSession =
    let rbio = BIO_new(BIO_s_mem())
    let wbio = BIO_new(BIO_s_mem())
    if rbio == nil or wbio == nil:
      SSL_free(ssl)
      raise newException(DtlsError, "BIO_new() failed")
    SSL_set_bio(ssl, rbio, wbio)

    # Memory BIOs cannot report an MTU: disable MTU queries, set link MTU.
    discard SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU)
    discard SSL_ctrl(ssl, DTLS_CTRL_SET_LINK_MTU, srv.config.mtu.cint, nil)

    result = DtlsSession(
      ssl:            ssl,
      rbio:           rbio,
      wbio:           wbio,
      peer:           normPeer(peer),
      peerKey:        addrKey(peer),
      state:          DtlsHandshaking,
      createdAtMs:    monoMs(),
      lastActivityMs: monoMs(),
      retryTimer:     TimerId(0),
      flushTimer:     TimerId(0),
      server:         srv)

    ensureExDataIdx()
    discard SSL_set_ex_data(ssl, gExDataIdx, cast[pointer](result))

    case srv.ctx.role
    of DtlsServerRole:
      SSL_set_accept_state(ssl)
    of DtlsClientRole:
      SSL_set_connect_state(ssl)

    srv.sessions[result.peerKey] = result

  proc handleDatagram(srv: DtlsServer; peer: Sockaddr_storage;
                      data: openArray[byte]) =
    ## Demux one inbound datagram to its session, creating server-side state
    ## only for plausible ClientHellos under the session cap.
    let key = addrKey(peer)
    let sess = srv.sessions.getOrDefault(key, nil)
    if sess == nil:
      # Unknown peer.
      if srv.ctx.role != DtlsServerRole or not looksLikeClientHello(data):
        return
      if srv.sessions.len >= srv.config.maxSessions:
        return                    # cap reached; cookie-less flood stops here
      let ssl = SSL_new(srv.ctx.ctx)
      if ssl == nil:
        return
      let fresh = srv.createSession(peer, ssl)
      inc srv.handshakes
      # Feeding now either emits HelloVerifyRequest (cookies on) or runs the
      # whole handshake (cookies off).
      fresh.feedDatagram(data)
      return

    if sess.state == DtlsClosed:
      return
    sess.lastActivityMs = monoMs()
    sess.feedDatagram(data)

  # ── Sweeper ────────────────────────────────────────────────────────────────

  proc sweep(srv: DtlsServer) {.gcsafe.} =
    ## Reap sessions that exceeded their handshake or idle budget.
    let now = monoMs()
    var doomed: seq[string]
    for key, sess in srv.sessions:
      let age = now - sess.lastActivityMs
      case sess.state
      of DtlsHandshaking:
        if now - sess.createdAtMs > srv.config.handshakeTimeoutMs.int64:
          doomed.add(key)
      of DtlsActive:
        if age > srv.config.idleTimeoutMs.int64:
          doomed.add(key)
      of DtlsClosed:
        doomed.add(key)
    for key in doomed:
      if key in srv.sessions:     # callbacks may have closed some already
        srv.sessions[key].close()

  # ── Contexts ───────────────────────────────────────────────────────────────

  proc newServerDtlsContext*(certFile, keyFile: string;
                             cookieExchange = true): DtlsContext =
    ## DTLS 1.2 server context loaded from a PEM certificate/key pair.
    ## The cookie exchange (stateless DoS mitigation) is on by default.
    let methodPtr = DTLS_server_method()
    if methodPtr == nil:
      raise newException(DtlsError, "DTLS_server_method() failed")
    let ctx = SSL_CTX_new(methodPtr)
    if ctx == nil:
      raise newException(DtlsError, "SSL_CTX_new() failed")

    # Pin to DTLS 1.2 only.
    discard SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION,
                         DTLS1_2_VERSION.cint, nil)
    discard SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION,
                         DTLS1_2_VERSION.cint, nil)

    if cookieExchange:
      ensureExDataIdx()
      discard SSL_CTX_set_options(ctx, SSL_OP_COOKIE_EXCHANGE)
      SSL_CTX_set_cookie_generate_cb(ctx, cookieGenCb)
      SSL_CTX_set_cookie_verify_cb(ctx, cookieVerifyCb)

    if SSL_CTX_use_certificate_file(ctx, certFile.cstring,
                                    SSL_FILETYPE_PEM) != 1:
      let err = opensslError()
      SSL_CTX_free(ctx)
      raise newException(DtlsError, "certificate load failed: " & err)
    if SSL_CTX_use_PrivateKey_file(ctx, keyFile.cstring,
                                   SSL_FILETYPE_PEM) != 1:
      let err = opensslError()
      SSL_CTX_free(ctx)
      raise newException(DtlsError, "private key load failed: " & err)
    if SSL_CTX_check_private_key(ctx) != 1:
      let err = opensslError()
      SSL_CTX_free(ctx)
      raise newException(DtlsError, "certificate/private key mismatch: " & err)

    result = DtlsContext(ctx: ctx, role: DtlsServerRole)

  proc newClientDtlsContext*(verifyPeer = false): DtlsContext =
    ## DTLS 1.2 client context. With `verifyPeer` the chain is checked against
    ## the system CA store; self-signed servers need `false`.
    let methodPtr = DTLS_client_method()
    if methodPtr == nil:
      raise newException(DtlsError, "DTLS_client_method() failed")
    let ctx = SSL_CTX_new(methodPtr)
    if ctx == nil:
      raise newException(DtlsError, "SSL_CTX_new() failed")
    discard SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION,
                         DTLS1_2_VERSION.cint, nil)
    discard SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION,
                         DTLS1_2_VERSION.cint, nil)
    if verifyPeer:
      if SSL_CTX_set_default_verify_paths(ctx) != 1:
        SSL_CTX_free(ctx)
        raise newException(DtlsError, "verify paths setup failed")
      SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nil)
    else:
      SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nil)
    result = DtlsContext(ctx: ctx, role: DtlsClientRole)

  # ── Server ─────────────────────────────────────────────────────────────────

  proc newDtlsServer*(loop: Loop; address: string; port: int;
                      ctx: DtlsContext;
                      onData: proc(sess: DtlsSession; data: openArray[byte]) {.closure.};
                      onHandshakeDone: proc(sess: DtlsSession) {.closure.} = nil;
                      onClose: proc(sess: DtlsSession) {.closure.} = nil;
                      onError: proc(sess: DtlsSession; msg: string) {.closure.} = nil;
                      config = defaultDtlsConfig()): DtlsServer =
    ## Bind a DTLS 1.2 server on `address:port`. One UDP socket multiplexes all
    ## peers; each gets a `DtlsSession` once it sends a ClientHello.
    ##
    ## `onError` fires for fatal session errors (handshake failures, alerts,
    ## read/write errors) followed by `onClose`; user-initiated `close()`
    ## produces only `onClose`.
    if ctx.role != DtlsServerRole:
      raise newException(DtlsError, "expected a server DTLS context")
    result = DtlsServer(
      loop:     loop,
      ctx:      ctx,
      config:   config,
      sessions: initTable[string, DtlsSession](),
      handshakes: 0,
      sweepTimer: TimerId(0),
      onDataCb: onData,
      onHandshakeDoneCb: onHandshakeDone,
      onCloseCb: onClose,
      onErrorCb: onError)
    let srv = result
    result.sock = bindUdp(loop, address, port) do (sender: Sockaddr_storage, data: openArray[byte]):
      srv.handleDatagram(sender, data)
    if config.sweepIntervalMs > 0:
      result.sweepTimer = loop.addInterval(config.sweepIntervalMs) do (id: int):
        srv.sweep()

  proc sessionCount*(srv: DtlsServer): int {.inline.} =
    ## Number of live (handshaking or active) sessions.
    srv.sessions.len

  proc close*(srv: DtlsServer) =
    ## Close every session and the underlying socket.
    if srv.sweepTimer != TimerId(0):
      srv.loop.cancelTimer(srv.sweepTimer)
      srv.sweepTimer = TimerId(0)
    for key in toSeq(srv.sessions.keys):
      srv.sessions[key].close()
    srv.sessions.clear()
    if srv.sock != nil:
      srv.sock.close()
      srv.sock = nil

  proc sendTo*(srv: DtlsServer; peerKey: string; data: openArray[byte]): int =
    ## Send app data by address key (as delivered in `onClose`/sweep contexts).
    let sess = srv.sessions.getOrDefault(peerKey, nil)
    if sess == nil:
      return -1
    sess.send(data)

  # ── Client ─────────────────────────────────────────────────────────────────

  proc connectDtls*(loop: Loop; address: string; port: int;
                    ctx: DtlsContext;
                    onData: proc(sess: DtlsSession; data: openArray[byte]) {.closure.} = nil;
                    onHandshakeDone: proc(sess: DtlsSession) {.closure.} = nil;
                    onClose: proc(sess: DtlsSession) {.closure.} = nil;
                    onError: proc(sess: DtlsSession; msg: string) {.closure.} = nil;
                    config = defaultDtlsConfig()): DtlsSession =
    ## Open a client-side DTLS session to `address:port` and start the
    ## handshake immediately (the first datagram is the ClientHello).
    if ctx.role != DtlsClientRole:
      raise newException(DtlsError, "expected a client DTLS context")
    var srv = DtlsServer(
      loop:     loop,
      ctx:      ctx,
      config:   config,
      sessions: initTable[string, DtlsSession](),
      handshakes: 0,
      sweepTimer: TimerId(0),
      onDataCb: onData,
      onHandshakeDoneCb: onHandshakeDone,
      onCloseCb: onClose,
      onErrorCb: onError)

    let sock = connectUdp(loop, address, port) do (sender: Sockaddr_storage,
                                                   data: openArray[byte]):
      srv.handleDatagram(sender, data)
    srv.sock = sock               # drainWriteBio sends through this
    srv.connectedSock = true

    let ssl = SSL_new(ctx.ctx)
    if ssl == nil:
      raise newException(DtlsError, "SSL_new() failed")
    result = srv.createSession(resolveAddr(address, port, SOCK_DGRAM), ssl)
    result.ownSock = sock
    inc srv.handshakes
    result.driveHandshake()       # emit the ClientHello right away
