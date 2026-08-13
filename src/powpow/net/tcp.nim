# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/net/tcp.nim — Non-blocking TCP server and client connections.
##
## This module provides a non-blocking TCP server and client implementation using the powpow event loop.
## It supports connection pooling, zero-copy file sending, and efficient read/write buffering.
##
## Both backends share this single module, selected at compile time:
##   - readiness (default): connections are watched for {Read}/{Write} and I/O
##     happens synchronously in the event callbacks (recv/send/accept/connect).
##   - io_uring (`when iouEnabled`): I/O is submitted to the ring — one-shot
##     `IORING_OP_ACCEPT`/`RECV`/`SEND`/`CONNECT` per connection, one in flight
##     each; TLS runs over OpenSSL memory-BIOs; close() drains pending writes
##     before tearing the socket down.
## The public API, pooling, close semantics and connect fallback are shared.

import std/[tables, strutils]
import ../types
when not defined(windows):
  import std/posix
import ../loop
import ../net/common
import dns
when iouEnabled:
  import ../io/uring

export loop.acquireBuf, loop.releaseBuf

const
  MaxBufPoolSize* = 1024
  MaxConnPoolSize* = 1024
  ConnectTimeoutMs = 3000
    ## How long a non-blocking connect may stay in progress before it is treated
    ## as failed and the next resolved address is tried. On some platforms a
    ## connect to an unreachable/refused address can hang without producing a
    ## writable event (e.g. Windows loopback to an unused 127.0.0.x), so the
    ## multi-address fallback must not depend on the OS refusing promptly.
  MaxWriteBufferSize = 32 * 1024 * 1024
    ## Per-connection cap on the queued write buffer. A client that stops
    ## reading while the server writes a large response (e.g. a TLS file
    ## download) must not make the server accumulate the whole payload in RAM
    ## per connection (slow-read memory DoS).
  MaxRetainedBufferCap = 65536
    ## Pooled connections keep their writeBuf/tlsCoalesce capacity so the pool
    ## does not re-allocate per request. Above this cap the capacity is dropped
    ## on release — an idle pooled connection must not pin a huge buffer it
    ## once needed for a single large response.

proc trimRetainedBuffer(buf: var seq[byte]) {.inline.} =
  ## Drop a pooled connection's buffer capacity when it exceeds the retained
  ## cap, so an idle pooled connection does not pin a huge once-used buffer.
  if buf.capacity > MaxRetainedBufferCap:
    buf = @[]

proc setLinger0(fd: SocketHandle) {.inline.} =
  var lin {.noInit.}: TLinger
  when defined(windows):
    lin.l_onoff = 1.cushort
    lin.l_linger = 0.cushort
  else:
    lin.l_onoff = 1.cint
    lin.l_linger = 0.cint
  discard setsockopt(fd, SOL_SOCKET, SO_LINGER, addr lin, sizeof(lin).SockLen)

when not defined(windows):
  const NI_MAXHOST = 1025
  const NI_NUMERICHOST = 1

proc formatIp(saAddr: Sockaddr_storage): string =
  var host: array[NI_MAXHOST, char]
  let sa = cast[ptr Sockaddr](unsafeAddr saAddr)
  let salen = getSockLen(unsafeAddr saAddr)
  when defined(windows):
    if getnameinfo(sa, salen, cast[cstring](addr host[0]), NI_MAXHOST.DWORD, nil, 0, NI_NUMERICHOST) == 0:
      result = $cast[cstring](addr host[0])
    else:
      result = "unknown"
  else:
    if getnameinfo(sa, salen, cast[cstring](addr host[0]), host.len.SockLen,
                   nil, 0, NI_NUMERICHOST) == 0:
      result = $cast[cstring](addr host[0])
    else:
      result = "unknown"

# ── Types ────────────────────────────────────────────────────────────────────

when iouEnabled:
  type
    SendFileState = enum
      sfIdle
      sfReading
      sfSending

  const
    MaxEagainRetries = 1

type
  ConnState* = enum
    Connecting
    Connected
    Closing
    Closed

  Connection* = ref object
    fd*:              SocketHandle
    loop*:            Loop
    server*:          TcpServer
    state*:           ConnState
    clientIp*:        string
    readBuf:          ptr UncheckedArray[byte]
    readBufLen:       int
    writeBuf:         seq[byte]
    writePos:         int
    tlsCoalesce:      seq[byte]   ## Reused TLS sendv coalesce buffer
    corked:           bool
    closeAfterFlush:  bool
    sendFileFd*:      int
    sendFileOff*:     int64
    sendFileRemain*:  int64
    data*:            pointer
    clientAddr:       Sockaddr_storage
    ssl*:             pointer
    tlsState*:        TlsState
    when iouEnabled:
      connectAddr:    Sockaddr_storage   # persistent IORING_OP_CONNECT target
      closeAfterDrain: bool
      onDataCb:       OnData
      onCloseCb:      OnClose
      readToken:      uint64
      writeToken:     uint64
      connectToken:   uint64
      sendFileToken:  uint64
      sendChunk:      seq[byte]
      sendState:      SendFileState
      shutdownAfterSend: bool
      closePending:   bool
      takeoverCbSet:  bool
      sendEagainRetries: int
      tlsOutBuf:      seq[byte]   # encrypted output drained from the SSL write BIO
      tlsOutPos:      int
      tlsWriteToken:  uint64

  OnAccept*  = proc(conn: Connection) {.closure.}
  OnData*    = proc(conn: Connection, data: openArray[byte]) {.closure.}
  OnClose*   = proc(conn: Connection) {.closure.}
  OnError*   = proc(err: string) {.closure.}

  TcpServer* = ref object
    fd*:       SocketHandle
    loop*:     Loop
    onAccept:  OnAccept
    onData:    OnData
    onClose*:  OnClose
    connPool*: seq[Connection]
    fdConn:    Table[int, Connection]
    unixPath:  string
    maxConnections*: int
    when iouEnabled:
      acceptToken: uint64
      acceptAddr: Sockaddr_storage
      acceptAddrLen: SockLen
    else:
      sharedCb:  FdCallback

proc newConnection*(fd: SocketHandle, loop: Loop, server: TcpServer,
                    readBuf: ptr UncheckedArray[byte], readBufLen: int): Connection {.inline.} =
  Connection(
    fd: fd, loop: loop, server: server, state: Closed,
    readBuf: readBuf, readBufLen: readBufLen,
    sendFileFd: -1)

proc shutWrVal(): cint {.inline.} =
  when defined(windows): 1 else: SHUT_WR

proc getClientIp*(conn: Connection): string {.inline.} =
  if conn.clientIp.len == 0 and conn.fd.int >= 0:
    conn.clientIp = formatIp(conn.clientAddr)
  conn.clientIp

proc getClientSockAddr*(conn: Connection): Sockaddr_storage {.inline.} =
  ## Return the client's raw socket address (set at accept/connect time).
  conn.clientAddr

when iouEnabled:
  import ./tlsapi

  # ── io_uring backend (submission-based) ─────────────────────────────

  type
    HandshakeState = enum
      hsDone, hsWantRead, hsWantWrite, hsError

  proc tlsFree(conn: Connection) {.gcsafe.} =
    if conn.ssl != nil:
      discard SSL_shutdown(cast[SslPtr](conn.ssl))
      SSL_free(cast[SslPtr](conn.ssl))
      conn.ssl = nil
    conn.tlsState = TlsOff

  # Forward declarations (TLS + write paths, defined below `close`).
  proc driveHandshake*(conn: Connection): bool {.gcsafe.}
  proc tlsRead*(conn: Connection, buf: pointer, count: int): int {.gcsafe.}
  proc tlsWrite*(conn: Connection, buf: pointer, count: int): int {.gcsafe.}
  proc armRead(conn: Connection) {.gcsafe.}
  proc armWrite(conn: Connection) {.gcsafe.}
  proc pumpSendFile(conn: Connection)
  proc fireClose(conn: Connection)
  proc afterData(conn: Connection)
  proc handleTlsData(conn: Connection, data: ptr UncheckedArray[byte], n: int)
  proc tlsSend(conn: Connection, data: openArray[byte]) {.gcsafe.}
  proc sslPutRead(conn: Connection, buf: ptr UncheckedArray[byte], n: int) {.gcsafe.}
  proc pumpBioWrite(conn: Connection) {.gcsafe.}
  proc armTlsWrite(conn: Connection) {.gcsafe.}
  proc releaseConnection(server: TcpServer, conn: Connection)

  # ── Connection ───────────────────────────────────────────────────────────────

  proc finishClose(conn: Connection) {.gcsafe.} =
    ## Actual socket teardown, extracted so `close` can defer it until pending
    ## writes (in-flight SEND ops) have delivered their bytes.
    if conn.fd.int >= 0:
      setLinger0(conn.fd)
      conn.loop.unregisterFd(conn.fd.int)
      if conn.ssl != nil:
        conn.tlsFree()
      sockClose(conn.fd)
      conn.fd = SocketHandle(-1)
    conn.writeBuf.setLen(0)
    conn.writePos = 0

  proc close*(conn: Connection) {.gcsafe.} =
    if conn.state == Closed: return
    conn.state = Closed
    if conn.server != nil:
      conn.server.fdConn.del(conn.fd.int)
    if conn.sendFileFd >= 0:
      closeFile(conn.sendFileFd)
      conn.sendFileFd = -1
    if conn.readToken != 0:
      conn.loop.cancelOp(conn.readToken)
      conn.readToken = 0
    if conn.connectToken != 0:
      conn.loop.cancelOp(conn.connectToken)
      conn.connectToken = 0
    conn.loop.clearTakeoverCb(conn.fd.int)
    if conn.sendFileToken != 0:
      conn.loop.cancelOp(conn.sendFileToken)
      conn.sendFileToken = 0
    if conn.writeToken != 0 or conn.writeBuf.len > 0 or
       conn.tlsWriteToken != 0 or conn.tlsOutBuf.len > 0:
      # Pending writes: drain them first. A SEND queued by `send` immediately
      # before `close` (e.g. a WebSocket close frame) must still deliver its
      # bytes; the write machinery finishes the teardown once drained.
      conn.closePending = true
      conn.closeAfterFlush = true
      conn.armWrite()
      conn.armTlsWrite()
    else:
      conn.finishClose()

  proc queueWrite(conn: Connection, data: openArray[byte]): bool {.gcsafe.} =
    if data.len == 0:
      return true
    if conn.writeBuf.len + data.len > MaxWriteBufferSize:
      conn.close()
      return false
    let oldLen = conn.writeBuf.len
    conn.writeBuf.setLen(oldLen + data.len)
    copyMem(addr conn.writeBuf[oldLen], unsafeAddr data[0], data.len)
    true

  proc socketWritableWait(conn: Connection) =
    ## One-shot POLL_ADD Write watcher: retry the write pump once the socket is
    ## writable again (a SEND completed with -EAGAIN).
    conn.loop.register(conn.fd.int, {Write}) do (fd: int, ev: set[EventType]):
      conn.loop.unregister(fd)
      conn.sendEagainRetries = 0
      conn.armWrite()
      conn.armTlsWrite()
      conn.pumpSendFile()

  proc handleSendEagain(conn: Connection) =
    ## FAST_POLL write retry: on the first SEND -EAGAIN, re-queue the send
    ## immediately instead of taking a POLL_ADD/POLLOUT completion round-trip.
    ## If the socket drained in between (small buffered writes, a fast peer) the
    ## retry succeeds with no extra wait; if it is still full the retry EAGAINs
    ## once more and we fall back to the POLLOUT watcher, so we never spin.
    if conn.sendEagainRetries < MaxEagainRetries:
      inc conn.sendEagainRetries
      if conn.tlsState != TlsOff:
        conn.armTlsWrite()
      else:
        conn.armWrite()
    else:
      conn.sendEagainRetries = 0
      conn.socketWritableWait()

  # ── Read path ────────────────────────────────────────────────────────────────

  proc onReadComplete(conn: Connection, token: uint64, res: int32, flags: uint32) =
    if conn.readToken != token:
      # Stale completion from a previous lifecycle (a pooled connection reused
      # for a new client); the current read token belongs to a newer op.
      return
    conn.readToken = 0
    if conn.state == Closed or conn.state == Connecting:
      return
    if res == -ECANCELED:
      # Deliberately canceled (e.g. a higher layer took the fd over with its own
      # readiness watcher); the connection is managed by that layer now.
      return
    if res < 0:
      if res == -ECONNRESET or res == -ECONNABORTED or res == -ENOTCONN or
         res == -EPIPE or res == -ECONNREFUSED:
        conn.close()
        conn.fireClose()
      else:
        # EAGAIN / spurious: keep reading
        conn.armRead()
      return
    if res == 0:
      # EOF (peer closed or shutdown)
      conn.close()
      conn.fireClose()
      return
    if conn.state != Connected:
      # write side shut down (graceful close): discard stragglers, wait for FIN
      conn.armRead()
      return
    if conn.tlsState != TlsOff:
      # Feed the ciphertext to SSL and deliver plaintext via the TLS path.
      conn.handleTlsData(cast[ptr UncheckedArray[byte]](conn.readBuf), res)
      conn.afterData()
      if conn.state == Closed: return
      conn.armRead()
      return
    if conn.onDataCb != nil:
      conn.onDataCb(conn, conn.readBuf.toOpenArray(0, res - 1))
    elif conn.server != nil and conn.server.onData != nil:
      conn.server.onData(conn, conn.readBuf.toOpenArray(0, res - 1))
    conn.afterData()
    if conn.state == Closed:
      return
    conn.armRead()

  proc armRead(conn: Connection) {.gcsafe.} =
    if conn.state != Connected and conn.state != Closing:
      return
    if conn.readToken != 0:
      return
    if conn.loop.isWatched(conn.fd.int):
      # A higher layer took the connection over with its own readiness watcher
      # (e.g. the HTTP client or standalone WebSocket server); it owns the reads.
      return
    if not conn.takeoverCbSet:
      conn.takeoverCbSet = true
      conn.loop.setTakeoverCb(conn.fd.int, proc() =
        if conn.readToken != 0:
          conn.loop.cancelOp(conn.readToken)
          conn.readToken = 0)
    let sqe = conn.loop.getOpSqe()
    if sqe == nil:
      conn.loop.deferCall(proc() =
        if conn.state != Closed:
          conn.armRead())
      return
    sqe.opcode = IORING_OP_RECV.uint8
    sqe.fd = conn.fd.int32
    sqe.paddr = cast[uint64](conn.readBuf)
    sqe.len = conn.readBufLen.uint32
    conn.readToken = conn.loop.commitOp(sqe, proc(token: uint64, res: int32, flags: uint32) =
      conn.onReadComplete(token, res, flags))

  # ── Write path ───────────────────────────────────────────────────────────────

  proc onWriteComplete(conn: Connection, token: uint64, res: int32, flags: uint32) =
    if conn.writeToken != token:
      return
    conn.writeToken = 0
    if conn.state != Connected and conn.state != Closing and not conn.closePending:
      return
    if res == -ECANCELED:
      return
    if res < 0:
      if res == -EAGAIN:
        conn.handleSendEagain()
        return
      if conn.closePending:
        # The peer is gone before the pending writes drained; tear down now.
        conn.closePending = false
        conn.finishClose()
        return
      if res == -ECONNRESET or res == -ECONNABORTED or res == -EPIPE or
         res == -ENOTCONN or res == -ECONNREFUSED:
        conn.close()
        conn.fireClose()
        return
      conn.close()
      conn.fireClose()
      return
    if conn.writePos + res > conn.writeBuf.len:
      conn.close()
      return
    conn.writePos += res
    conn.sendEagainRetries = 0
    if conn.writePos >= conn.writeBuf.len:
      conn.writeBuf.setLen(0)
      conn.writePos = 0
      if conn.corked:
        setTcpCork(conn.fd, false)
        conn.corked = false
      if conn.closePending:
        conn.closePending = false
        conn.finishClose()
        if conn.server != nil:
          conn.server.releaseConnection(conn)
        else:
          if conn.readBuf != nil:
            releaseBuf(conn.loop, conn.readBuf)
            conn.readBuf = nil
      elif conn.sendFileFd >= 0:
        conn.pumpSendFile()
      elif conn.closeAfterFlush:
        conn.close()
        conn.fireClose()
      elif conn.shutdownAfterSend:
        conn.state = Closing
        sockShutdown(conn.fd, shutWrVal())
      else:
        conn.armRead()
    else:
      conn.armWrite()

  proc armWrite(conn: Connection) {.gcsafe.} =
    if conn.writeToken != 0 or conn.writeBuf.len == 0:
      return
    if conn.tlsState != TlsOff:
      # TLS conns never send raw plaintext; ciphertext goes through armTlsWrite.
      return
    if conn.state != Connected and conn.state != Closing and not conn.closePending:
      return
    let start = conn.writePos
    let sqe = conn.loop.getOpSqe()
    if sqe == nil:
      conn.loop.deferCall(proc() =
        if conn.state != Closed:
          conn.armWrite())
      return
    sqe.opcode = IORING_OP_SEND.uint8
    sqe.fd = conn.fd.int32
    sqe.paddr = cast[uint64](addr conn.writeBuf[start])
    sqe.len = (conn.writeBuf.len - start).uint32
    conn.writeToken = conn.loop.commitOp(sqe, proc(token: uint64, res: int32, flags: uint32) =
      conn.onWriteComplete(token, res, flags))

  # ── sendfile (READ + SEND pump) ──────────────────────────────────────────────

  proc sendFileSendChunk(conn: Connection, n: int) =
    conn.sendState = sfSending
    conn.writeToken = conn.loop.submitOp(proc(sqe: ptr IoUringSqe) =
        sqe.opcode = IORING_OP_SEND.uint8
        sqe.fd = conn.fd.int32
        sqe.paddr = cast[uint64](addr conn.sendChunk[0])
        sqe.len = n.uint32
      , proc(token: uint64, res2: int32, flags2: uint32) =
        if conn.writeToken != token:
          return
        conn.writeToken = 0
        if conn.state == Closed:
          return
        if res2 <= 0:
          conn.close()
          conn.fireClose()
          return
        conn.sendFileOff += res2.int64
        conn.sendFileRemain -= res2.int64
        conn.sendState = sfIdle
        conn.pumpSendFile())

  proc pumpSendFile(conn: Connection) =
    if conn.sendFileFd < 0:
      if conn.writeBuf.len > 0:
        conn.armWrite()
      elif conn.closeAfterFlush:
        conn.close()
        conn.fireClose()
      return
    if conn.writeToken != 0 or conn.sendFileToken != 0:
      return
    if conn.writeBuf.len > 0:
      conn.armWrite()
      return
    case conn.sendState
    of sfIdle:
      if conn.sendFileRemain <= 0:
        closeFile(conn.sendFileFd)
        conn.sendFileFd = -1
        conn.sendState = sfIdle
        conn.pumpSendFile()
        return
      if conn.sendChunk.len == 0:
        conn.sendChunk = newSeq[byte](SendFileChunkSize)
      let toRead = min(conn.sendFileRemain, SendFileChunkSize.int64).int
      conn.sendState = sfReading
      conn.sendFileToken = conn.loop.submitOp(proc(sqe: ptr IoUringSqe) =
          sqe.opcode = IORING_OP_READ.uint8
          sqe.fd = conn.sendFileFd.int32
          sqe.paddr = cast[uint64](addr conn.sendChunk[0])
          sqe.len = toRead.uint32
          sqe.off = conn.sendFileOff.uint64
        , proc(token: uint64, res: int32, flags: uint32) =
          if conn.sendFileToken != token:
            return
          conn.sendFileToken = 0
          if conn.state == Closed:
            return
          if res <= 0:
            closeFile(conn.sendFileFd)
            conn.sendFileFd = -1
            conn.sendState = sfIdle
            conn.pumpSendFile()
            return
          conn.sendFileSendChunk(res))
    of sfReading, sfSending:
      discard

  proc continueSendFile*(conn: Connection): bool =
    ## Public API parity with net/tcp.nim: kick the op-driven sendfile pump.
    conn.pumpSendFile()
    true

  proc flushWriteBuffer*(conn: Connection): bool =
    ## API parity with net/tcp.nim (used by the standalone WebSocket server's
    ## Write-watcher path). Writes are submitted asynchronously via SEND ops, so
    ## this just kicks the pump and reports whether the buffer is currently empty.
    conn.armWrite()
    conn.writeBuf.len == 0 and conn.writeToken == 0

  # ── Connection API ───────────────────────────────────────────────────────────

  proc send*(conn: Connection, data: openArray[byte]): int {.gcsafe.} =
    if conn.state != Connected: return 0
    if conn.tlsState != TlsOff:
      conn.tlsSend(data)
      if conn.state == Closed: return -1
      return data.len
    if not conn.queueWrite(data):
      return 0
    if not conn.corked:
      setTcpCork(conn.fd, true)
      conn.corked = true
    conn.armWrite()
    data.len

  proc send*(conn: Connection, data: string): int {.gcsafe.} =
    conn.send(data.toOpenArrayByte(0, data.high))

  proc sendv*(conn: Connection,
              parts: openArray[tuple[data: ptr UncheckedArray[byte],
                                     len: int]]): int =
    if conn.state != Connected: return 0
    var totalLen = 0
    for part in parts:
      totalLen += part.len
    if totalLen == 0: return 0
    if conn.tlsState != TlsOff:
      conn.tlsCoalesce.setLen(totalLen)
      var pos = 0
      for part in parts:
        copyMem(addr conn.tlsCoalesce[pos], part.data, part.len)
        pos += part.len
      return conn.send(conn.tlsCoalesce)
    if conn.writeBuf.len > 0:
      for part in parts:
        if part.len > 0:
          if not conn.queueWrite(part.data.toOpenArray(0, part.len - 1)):
            return 0
      if not conn.corked:
        setTcpCork(conn.fd, true)
        conn.corked = true
      conn.armWrite()
      return totalLen
    # Fast path: coalesce into the write buffer and send in one op.
    let oldLen = conn.writeBuf.len
    conn.writeBuf.setLen(oldLen + totalLen)
    var pos = oldLen
    for part in parts:
      copyMem(addr conn.writeBuf[pos], part.data, part.len)
      pos += part.len
    if not conn.corked:
      setTcpCork(conn.fd, true)
      conn.corked = true
    conn.armWrite()
    totalLen

  proc shutdown*(conn: Connection) {.gcsafe.} =
    if conn.state != Connected: return
    if conn.writeBuf.len > 0:
      conn.shutdownAfterSend = true
      conn.armWrite()
    else:
      conn.state = Closing
      sockShutdown(conn.fd, shutWrVal())

  proc closeAfterDrain*(conn: Connection) {.inline, gcsafe.} =
    if conn.state == Closed: return
    if conn.writeBuf.len == 0 and conn.sendFileFd < 0:
      when defined(linux):
        if conn.tlsState == TlsOff:
          conn.state = Closing
          sockShutdown(conn.fd, shutWrVal())
          conn.armRead()
        else:
          conn.close()
      else:
        conn.close()
    else:
      conn.closeAfterFlush = true
      conn.armWrite()

  proc closeAndRelease*(conn: Connection) {.inline, gcsafe.} =
    conn.close()
    if conn.readBuf != nil:
      releaseBuf(conn.loop, conn.readBuf)
      conn.readBuf = nil

  proc fireClose(conn: Connection) =
    if conn.closePending:
      # close() deferred the teardown until pending writes drain; onWriteComplete
      # finishes the socket and releases the connection.
      return
    if conn.server != nil:
      let srv = conn.server
      if srv.onClose != nil: srv.onClose(conn)
      srv.releaseConnection(conn)
    else:
      if conn.onCloseCb != nil: conn.onCloseCb(conn)
      conn.closeAndRelease()

  proc afterData(conn: Connection) =
    ## Post-`onData` semantics mirroring net/tcp.nim's handleClientRead: if the
    ## application changed the connection state while handling data (close /
    ## graceful close), notify onClose; release pooled connections once closed.
    if conn.state != Connected:
      if conn.server != nil and conn.server.onClose != nil:
        conn.server.onClose(conn)
      elif conn.onCloseCb != nil:
        conn.onCloseCb(conn)
      if conn.state == Closed and not conn.closePending:
        if conn.server != nil:
          conn.server.releaseConnection(conn)
        else:
          conn.closeAndRelease()



  # ── TLS (memory-BIO) ─────────────────────────────────────────────────────────

  proc sslPutRead(conn: Connection, buf: ptr UncheckedArray[byte], n: int) {.gcsafe.} =
    ## Feed `n` ciphertext bytes into the SSL read BIO (from a RECV completion).
    if conn.ssl == nil: return
    var bio = SSL_get_rbio(cast[SslPtr](conn.ssl))
    let written = BIO_write(bio, buf, n.cint)
    if written != n.cint:
      conn.close()

  proc tlsRead*(conn: Connection, buf: pointer, count: int): int {.gcsafe.} =
    if conn.ssl == nil: return -1
    let r = SSL_read(cast[SslPtr](conn.ssl), cast[cstring](buf), count.cint)
    if r > 0: return r
    let e = SSL_get_error(cast[SslPtr](conn.ssl), r)
    if e == SSL_ERROR_WANT_READ or e == SSL_ERROR_WANT_WRITE:
      return -2
    0

  proc tlsWrite*(conn: Connection, buf: pointer, count: int): int {.gcsafe.} =
    if conn.ssl == nil: return -1
    let r = SSL_write(cast[SslPtr](conn.ssl), cast[cstring](buf), count.cint)
    if r > 0: return r
    let e = SSL_get_error(cast[SslPtr](conn.ssl), r)
    if e == SSL_ERROR_WANT_READ or e == SSL_ERROR_WANT_WRITE:
      return -2
    -1

  proc tlsSend(conn: Connection, data: openArray[byte]) {.gcsafe.} =
    ## SSL_write then pump any ciphertext the BIO produced into the TLS output
    ## queue. Plaintext is only ever buffered (never sent raw): during the
    ## handshake it waits; when SSL_write reports WANT_WRITE the remainder waits
    ## and is re-fed once the encrypted queue drains.
    if conn.tlsState == TlsHandshaking:
      discard conn.queueWrite(data)
      return
    var pos = 0
    while pos < data.len:
      let n = conn.tlsWrite(unsafeAddr data[pos], data.len - pos)
      if n <= 0:
        if n == -2:
          conn.pumpBioWrite()
          break
        conn.close()
        return
      pos += n
    if pos < data.len:
      discard conn.queueWrite(data.toOpenArray(pos, data.len - 1))
    conn.pumpBioWrite()

  proc armTlsWrite(conn: Connection) {.gcsafe.} =
    ## Submit a SEND op for the encrypted output queued in `tlsOutBuf`. One
    ## in-flight at a time; on completion, buffered plaintext is re-fed through
    ## SSL once the queue drains.
    if conn.tlsWriteToken != 0 or conn.tlsOutBuf.len == 0:
      return
    if conn.state != Connected and conn.state != Closing and not conn.closePending:
      return
    let start = conn.tlsOutPos
    let sqe = conn.loop.getOpSqe()
    if sqe == nil:
      conn.loop.deferCall(proc() =
        if conn.state != Closed:
          conn.armTlsWrite())
      return
    sqe.opcode = IORING_OP_SEND.uint8
    sqe.fd = conn.fd.int32
    sqe.paddr = cast[uint64](addr conn.tlsOutBuf[start])
    sqe.len = (conn.tlsOutBuf.len - start).uint32
    conn.tlsWriteToken = conn.loop.commitOp(sqe, proc(token: uint64, res: int32, flags: uint32) =
      if conn.tlsWriteToken != token:
        return
      conn.tlsWriteToken = 0
      if conn.state != Connected and conn.state != Closing and not conn.closePending:
        return
      if res == -ECANCELED:
        return
      if res < 0:
        if res == -EAGAIN:
          conn.handleSendEagain()
          return
        if conn.closePending:
          conn.closePending = false
          conn.finishClose()
          return
        conn.close()
        conn.fireClose()
        return
      conn.tlsOutPos += res
      conn.sendEagainRetries = 0
      if conn.tlsOutPos >= conn.tlsOutBuf.len:
        conn.tlsOutBuf.setLen(0)
        conn.tlsOutPos = 0
        if conn.closePending:
          conn.closePending = false
          conn.finishClose()
          if conn.server != nil:
            conn.server.releaseConnection(conn)
          else:
            if conn.readBuf != nil:
              releaseBuf(conn.loop, conn.readBuf)
              conn.readBuf = nil
        elif conn.tlsState == TlsActive and conn.writeBuf.len > 0:
          # Re-feed plaintext buffered during WANT_WRITE once the encrypted queue
          # drains. During the handshake the buffered plaintext is flushed by
          # driveHandshake when the handshake completes (never re-queued).
          let data = conn.writeBuf
          conn.writeBuf.setLen(0)
          conn.writePos = 0
          conn.tlsSend(data)
      else:
        conn.armTlsWrite())

  proc pumpBioWrite(conn: Connection) {.gcsafe.} =
    ## Drain ciphertext queued in the SSL write BIO into the TLS output queue
    ## and submit it. TLS ciphertext never shares the raw writeBuf path.
    if conn.ssl == nil: return
    var bio = SSL_get_wbio(cast[SslPtr](conn.ssl))
    var buf: array[16 * 1024, byte]
    while true:
      let n = BIO_read(bio, addr buf[0], buf.len.cint)
      if n <= 0:
        break
      conn.tlsOutBuf.add(buf.toOpenArray(0, n - 1))
    if conn.tlsOutBuf.len > 0:
      conn.armTlsWrite()

  proc handleTlsData(conn: Connection, data: ptr UncheckedArray[byte], n: int) =
    conn.sslPutRead(data, n)
    case conn.tlsState
    of TlsHandshaking:
      discard conn.driveHandshake()
    of TlsActive:
      var outBuf: array[16 * 1024, byte]
      while true:
        let r = conn.tlsRead(addr outBuf[0], outBuf.len)
        if r == -2:
          break
        if r <= 0:
          break
        if conn.onDataCb != nil:
          conn.onDataCb(conn, outBuf.toOpenArray(0, r - 1))
        elif conn.server != nil and conn.server.onData != nil:
          conn.server.onData(conn, outBuf.toOpenArray(0, r - 1))
      conn.pumpBioWrite()
    of TlsOff:
      discard

  proc driveHandshake*(conn: Connection): bool {.gcsafe.} =
    ## Progress the memory-BIO TLS handshake. Returns true when TLS is active.
    ## With memory BIOs, every SSL_do_handshake call may write ciphertext to the
    ## write BIO (e.g. the client's ClientHello on the first call, which returns
    ## WANT_READ), so the BIO is drained after every attempt regardless of the
    ## WANT_READ/WANT_WRITE result.
    if conn.ssl == nil or conn.tlsState == TlsActive:
      return true
    let r = SSL_do_handshake(cast[SslPtr](conn.ssl))
    conn.pumpBioWrite()
    if r == 1:
      conn.tlsState = TlsActive
      if conn.writeBuf.len > 0:
        # Flush plaintext buffered while the handshake was in progress.
        let data = conn.writeBuf
        conn.writeBuf.setLen(0)
        conn.writePos = 0
        conn.tlsSend(data)
      return true
    let e = SSL_get_error(cast[SslPtr](conn.ssl), r)
    if e == SSL_ERROR_WANT_READ or e == SSL_ERROR_WANT_WRITE:
      return false
    conn.close()
    false

  # ── Pooling ──────────────────────────────────────────────────────────────────

  proc acquireConnection(server: TcpServer, fd: SocketHandle): Connection {.gcsafe.} =
    if server.connPool.len > 0:
      result = server.connPool.pop()
      result.fd = fd
      result.sendFileFd = -1
      result.loop = server.loop
      result.server = server
      result.state = Connected
      result.ssl = nil
      result.tlsState = TlsOff
      result.readToken = 0
      result.writeToken = 0
      result.connectToken = 0
      result.sendState = sfIdle
      result.shutdownAfterSend = false
      result.closeAfterDrain = false
      result.closePending = false
      result.takeoverCbSet = false
      result.sendEagainRetries = 0
      result.tlsOutBuf.setLen(0)
      result.tlsOutPos = 0
      result.tlsWriteToken = 0
    else:
      result = Connection(
        fd:        fd,
        loop:      server.loop,
        server:    server,
        state:     Connected,
        sendFileFd: -1,
        readBuf:   acquireBuf(server.loop),
        readBufLen: DefaultBufSize,
      )

  proc releaseConnection(server: TcpServer, conn: Connection) =
    conn.state = Closed
    conn.fd = SocketHandle(-1)
    conn.corked = false
    conn.closeAfterFlush = false
    conn.closePending = false
    conn.tlsOutBuf.setLen(0)
    conn.tlsOutPos = 0
    conn.tlsWriteToken = 0
    conn.shutdownAfterSend = false
    conn.sendFileFd = -1
    conn.sendFileOff = 0
    conn.sendFileRemain = 0
    conn.sendState = sfIdle
    conn.writeBuf.setLen(0)
    conn.writePos = 0
    conn.writeBuf.trimRetainedBuffer()
    conn.tlsCoalesce.setLen(0)
    conn.tlsCoalesce.trimRetainedBuffer()
    conn.clientIp = ""
    conn.ssl = nil
    conn.tlsState = TlsOff
    if server.connPool.len < MaxConnPoolSize:
      server.connPool.add(conn)
    else:
      if conn.readBuf != nil:
        releaseBuf(conn.loop, conn.readBuf)
        conn.readBuf = nil

  # ── TcpServer ────────────────────────────────────────────────────────────────

  proc armAccept(server: TcpServer) =
    if server.acceptToken != 0:
      return
    server.acceptAddrLen = sizeof(server.acceptAddr).SockLen
    server.acceptToken = server.loop.submitOp(proc(sqe: ptr IoUringSqe) =
        sqe.opcode = IORING_OP_ACCEPT.uint8
        sqe.fd = server.fd.int32
        sqe.paddr = cast[uint64](addr server.acceptAddr)
        sqe.off = cast[uint64](addr server.acceptAddrLen)  # kernel 5.15: socklen_t* in addr2
      , proc(token: uint64, res: int32, flags: uint32) =
        if server.acceptToken != token:
          return
        server.acceptToken = 0
        if server.fd.int < 0:
          return
        if res < 0:
          if res != -EAGAIN and res != -EINTR:
            server.armAccept()
          else:
            server.armAccept()
          return
        let clientFd = SocketHandle(res)
        setNonBlocking(clientFd)
        setTcpNoDelay(clientFd)
        if server.maxConnections > 0 and
           server.fdConn.len >= server.maxConnections:
          sockClose(clientFd)
          server.armAccept()
          return
        let conn = server.acquireConnection(clientFd)
        conn.clientAddr = server.acceptAddr
        if server.onAccept != nil:
          server.onAccept(conn)
        if conn.state == Closed:
          server.releaseConnection(conn)
          server.armAccept()
          return
        server.fdConn[clientFd.int] = conn
        conn.armRead()
        server.armAccept())

  proc listen*(server: TcpServer, address: string, port: int) =
    let addrBuf = resolveAddr(address, port, SOCK_STREAM)
    let fd = socket(cast[ptr Sockaddr](addr addrBuf).sa_family.cint,
                    SOCK_STREAM, 0)
    if fd.cint < 0:
      raise newException(NetError, "socket() failed")

    setNonBlocking(fd)
    setReuseAddr(fd)
    setReusePort(fd)

    let sLen = getSockLen(addr addrBuf)
    if bindSocket(fd, cast[ptr Sockaddr](addr addrBuf), sLen) < 0:
      sockClose(fd)
      raise newException(NetError, "bind() failed")

    if listen(fd, SOMAXCONN) < 0:
      sockClose(fd)
      raise newException(NetError, "listen() failed")

    server.fd = fd
    server.armAccept()

  when not defined(windows):
    proc listenUnix*(server: TcpServer, path: string; mode: int = 0o660) =
      let fd = socket(AF_UNIX.cint, SOCK_STREAM, 0)
      if fd.cint < 0:
        raise newException(NetError, "socket(AF_UNIX) failed")

      setNonBlocking(fd)

      proc c_unlink(path: cstring): cint {.importc: "unlink", header: "<unistd.h>".}
      discard c_unlink(path.cstring)

      var sockAddr: Sockaddr_un
      sockAddr.sun_family = AF_UNIX.uint8
      let pathLen = path.len
      if pathLen > UNIX_PATH_MAX:
        sockClose(fd)
        raise newException(NetError,
          "Unix socket path \"" & path & "\" exceeds max length (" & $UNIX_PATH_MAX & ")")
      copyMem(addr sockAddr.sun_path[0], path.cstring, pathLen + 1)

      let sLen = (sizeof(sockAddr.sun_family) + pathLen + 1).SockLen
      if bindSocket(fd, cast[ptr Sockaddr](addr sockAddr), sLen) < 0:
        sockClose(fd)
        raise newException(NetError, "bind(AF_UNIX) failed for " & path)

      proc c_chmod(path: cstring, mode: cint): cint {.importc: "chmod", header: "<sys/stat.h>".}
      discard c_chmod(path.cstring, mode.cint)

      if listen(fd, SOMAXCONN) < 0:
        sockClose(fd)
        raise newException(NetError, "listen() failed on AF_UNIX socket")

      server.fd = fd
      server.unixPath = path
      server.armAccept()

  proc close*(server: TcpServer) {.gcsafe.} =
    for conn in server.connPool:
      if conn.readBuf != nil:
        releaseBuf(conn.loop, conn.readBuf)
        conn.readBuf = nil
    server.connPool.setLen(0)
    if server.acceptToken != 0:
      server.loop.cancelOp(server.acceptToken)
      server.acceptToken = 0
    if server.fd.int >= 0:
      server.loop.unregister(server.fd.int)
      sockClose(server.fd)
      server.fd = SocketHandle(-1)
    if server.unixPath.len > 0:
      when not defined(windows):
        proc c_unlink(path: cstring): cint {.importc: "unlink", header: "<unistd.h>".}
        discard c_unlink(server.unixPath.cstring)
      server.unixPath.setLen(0)

  proc injectFd*(server: TcpServer, clientFd: SocketHandle) =
    let conn = server.acquireConnection(clientFd)
    if server.onAccept != nil:
      server.onAccept(conn)
    if conn.state == Closed:
      return
    server.fdConn[clientFd.int] = conn
    conn.armRead()

  proc newTcpServer*(loop: Loop,
                     onData: OnData,
                     onAccept: OnAccept = nil,
                     onClose: OnClose = nil): TcpServer =
    let srv = TcpServer(
      fd:       SocketHandle(-1),
      loop:     loop,
      onAccept: onAccept,
      onData:   onData,
      onClose:  onClose,
      connPool: @[],
      fdConn:   initTable[int, Connection](64),
      unixPath: "",
      maxConnections: 0,
    )
    # Higher layers signal writability for an op-driven connection (e.g. the HTTP
    # server resumes a zero-copy sendfile after `modify(fd, {Read, Write})`); the
    # io_uring backend turns that into a one-shot POLL_ADD Write poll and resumes
    # the sendfile pump here.
    loop.addWritabilityHook(proc(fd: int) =
      let conn = srv.fdConn.getOrDefault(fd)
      if conn != nil and conn.sendFileFd >= 0:
        conn.pumpSendFile())
    srv

  # ── Client connect ───────────────────────────────────────────────────────────

  proc connect*(loop: Loop, address: string, port: int,
                onConnect: proc(conn: Connection) {.closure.},
                onData: OnData,
                onClose: OnClose = nil,
                onError: OnError = nil) =
    resolveAddrAsync(loop, address, port, SOCK_STREAM,
      proc(addrs: seq[Sockaddr_storage]; err: string) =
        if err.len > 0:
          if onError != nil:
            onError(err)
          return
        if addrs.len == 0:
          if onError != nil:
            onError("connect: no addresses resolved for " & address)
          return

        var tryIdx = 0
        var connTimer: TimerId = TimerId(0)
        proc attemptNext() {.closure.} =
          if connTimer != TimerId(0):
            loop.cancelTimer(connTimer)
            connTimer = TimerId(0)
          if tryIdx >= addrs.len:
            if onError != nil:
              onError("connect() failed on all resolved addresses for " & address)
            return
          let addrBuf = addrs[tryIdx]
          inc tryIdx

          let fd = socket(cast[ptr Sockaddr](addr addrBuf).sa_family.cint,
                          SOCK_STREAM, 0)
          if fd.cint < 0:
            if onError != nil:
              onError("socket() failed")
            return

          setNonBlocking(fd)
          setTcpNoDelay(fd)

          let conn = Connection(
            fd:        fd,
            loop:      loop,
            state:     Connecting,
            readBuf:   acquireBuf(loop),
            readBufLen: DefaultBufSize,
            onDataCb:  onData,
            onCloseCb: onClose,
          )
          let sLen = getSockLen(addr addrBuf)
          conn.connectAddr = addrBuf
          conn.connectToken = loop.submitOp(proc(sqe: ptr IoUringSqe) =
              sqe.opcode = IORING_OP_CONNECT.uint8
              sqe.fd = fd.int32
              sqe.paddr = cast[uint64](addr conn.connectAddr)
              sqe.off = sLen.uint64   # kernel 5.15: sockaddr length in addr2 (offset 8)
            , proc(token: uint64, res: int32, flags: uint32) =
              if conn.connectToken != token:
                return
              conn.connectToken = 0
              if connTimer != TimerId(0):
                loop.cancelTimer(connTimer)
                connTimer = TimerId(0)
              if conn.state == Closed:
                return
              if res < 0:
                conn.closeAndRelease()
                attemptNext()
                return
              conn.state = Connected
              conn.clientAddr = addrBuf
              onConnect(conn)
              if conn.state == Closed:
                return
              conn.armRead())
          if conn.connectToken == 0:
            conn.closeAndRelease()
            attemptNext()
            return
          connTimer = loop.addTimer(ConnectTimeoutMs) do (id: int):
            if conn.connectToken != 0:
              conn.closeAndRelease()
              attemptNext()
        attemptNext()
    )

  when not defined(windows):
    proc connectUnix*(loop: Loop; path: string;
                      onConnect: proc(conn: Connection) {.closure.};
                      onData: OnData;
                      onClose: OnClose = nil) =
      let fd = socket(AF_UNIX.cint, SOCK_STREAM, 0)
      if fd.cint < 0:
        raise newException(NetError, "socket(AF_UNIX) failed")

      setNonBlocking(fd)

      let conn = Connection(
        fd:        fd,
        loop:      loop,
        state:     Connecting,
        readBuf:   acquireBuf(loop),
        readBufLen: DefaultBufSize,
        onDataCb:  onData,
        onCloseCb: onClose,
      )

      var sockAddr: Sockaddr_un
      sockAddr.sun_family = AF_UNIX.uint8
      let pathLen = path.len
      if pathLen > UNIX_PATH_MAX:
        conn.closeAndRelease()
        raise newException(NetError,
          "Unix socket path \"" & path & "\" exceeds max length (" & $UNIX_PATH_MAX & ")")
      copyMem(addr sockAddr.sun_path[0], path.cstring, pathLen + 1)
      let sLen = (sizeof(sockAddr.sun_family) + pathLen + 1).SockLen
      copyMem(addr conn.connectAddr, addr sockAddr, sLen)

      conn.connectToken = loop.submitOp(proc(sqe: ptr IoUringSqe) =
          sqe.opcode = IORING_OP_CONNECT.uint8
          sqe.fd = fd.int32
          sqe.paddr = cast[uint64](addr conn.connectAddr)
          sqe.off = sLen.uint64   # kernel 5.15: sockaddr length in addr2 (offset 8)
        , proc(token: uint64, res: int32, flags: uint32) =
          if conn.connectToken != token:
            return
          conn.connectToken = 0
          if conn.state == Closed:
            return
          if res < 0:
            conn.closeAndRelease()
            raise newException(NetError, "connect(AF_UNIX) failed for " & path)
          conn.state = Connected
          onConnect(conn)
          if conn.state == Closed:
            return
          conn.armRead())
      if conn.connectToken == 0:
        conn.closeAndRelease()
        raise newException(NetError, "connect(AF_UNIX) ring full")

else:
  {.push gcsafe.}
  proc driveHandshake*(conn: Connection): bool
  proc tlsRead*(conn: Connection, buf: pointer, count: int): int
  proc tlsWrite*(conn: Connection, buf: pointer, count: int): int
  proc tlsFree*(conn: Connection)

  # ── Connection ───────────────────────────────────────────────────────────────

  proc close*(conn: Connection) =
    if conn.state == Closed: return
    conn.state = Closed
    if conn.server != nil:
      conn.server.fdConn.del(conn.fd.int)
    if conn.sendFileFd >= 0:
      closeFile(conn.sendFileFd)
      conn.sendFileFd = -1
    setLinger0(conn.fd)
    conn.loop.unregisterFd(conn.fd.int)
    if conn.ssl != nil:
      conn.tlsFree()
    sockClose(conn.fd)
    conn.fd = SocketHandle(-1)   # never close/register a reused fd via stale state
    conn.writeBuf.setLen(0)
    conn.writePos = 0

  proc queueWrite(conn: Connection, data: openArray[byte]): bool =
    ## Append `data` to the connection's write buffer, closing the connection if
    ## the buffer would exceed `MaxWriteBufferSize`. Returns true on success.
    if data.len == 0:
      return true
    if conn.writeBuf.len + data.len > MaxWriteBufferSize:
      conn.close()
      return false
    let oldLen = conn.writeBuf.len
    conn.writeBuf.setLen(oldLen + data.len)
    copyMem(addr conn.writeBuf[oldLen], unsafeAddr data[0], data.len)
    true

  proc flushWriteBuffer*(conn: Connection): bool =
    while conn.writePos < conn.writeBuf.len:
      let remaining = conn.writeBuf.len - conn.writePos
      let n = if conn.tlsState == TlsActive:
                conn.tlsWrite(unsafeAddr conn.writeBuf[conn.writePos], remaining)
              else:
                sockSend(conn.fd,
                         unsafeAddr conn.writeBuf[conn.writePos], remaining)
      if n < 0:
        if n == -2 or sockWouldBlock():
          if conn.corked:
            setTcpCork(conn.fd, false)
            conn.corked = false
          return false
        conn.close()
        return true

      conn.writePos += n

    conn.writeBuf.setLen(0)
    conn.writePos = 0
    if conn.corked:
      setTcpCork(conn.fd, false)
      conn.corked = false
    return true

  # ── TLS ───────────────────────────────────────────────────────────────────────
  # The connection carries an optional OpenSSL `SSL*` pointer (`ssl`). When set,
  # all reads/writes are routed through SSL_read/SSL_write and the handshake is
  # driven non-blockingly from the event loop (see wrapTls in net/tls.nim).

  when not defined(windows):
    import ./tlsapi

    type
      HandshakeState = enum
        hsDone, hsWantRead, hsWantWrite, hsError

    proc progressHandshake(conn: Connection): HandshakeState =
      ## Progress the non-blocking TLS handshake one step.
      if conn.ssl == nil: return hsDone
      let r = SSL_do_handshake(cast[SslPtr](conn.ssl))
      if r == 1:
        conn.tlsState = TlsActive
        return hsDone
      let e = SSL_get_error(cast[SslPtr](conn.ssl), r)
      if e == SSL_ERROR_WANT_READ: return hsWantRead
      if e == SSL_ERROR_WANT_WRITE: return hsWantWrite
      conn.close()
      hsError

    proc driveHandshake*(conn: Connection): bool =
      ## Advance the connection's TLS handshake (client kick-off or loop-driven
      ## progress). Returns true once TLS is active. Writes queued during the
      ## handshake are flushed on completion.
      ##
      ## OpenSSL may buffer handshake output and return WANT_WRITE (e.g. writing
      ## the ServerHello / client Finished). The connection must then be watched
      ## for writability — registering {Read} only deadlocks the handshake.
      if conn.ssl == nil or conn.tlsState == TlsActive:
        return true
      case conn.progressHandshake()
      of hsDone:
        if conn.writeBuf.len > 0:
          if not conn.flushWriteBuffer():
            conn.loop.modify(conn.fd.int, {Read, Write})
        return true
      of hsWantWrite:
        conn.loop.modify(conn.fd.int, {Read, Write})
        false
      of hsWantRead:
        conn.loop.modify(conn.fd.int, {Read})
        false
      of hsError:
        false

    proc tlsRead*(conn: Connection, buf: pointer, count: int): int =
      ## SSL_read wrapper. Returns bytes read, -2 when the operation would
      ## block, 0 on clean EOF or error (connection is closed by caller).
      if conn.ssl == nil: return -1
      let r = SSL_read(cast[SslPtr](conn.ssl), cast[cstring](buf), count.cint)
      if r > 0: return r
      let e = SSL_get_error(cast[SslPtr](conn.ssl), r)
      if e == SSL_ERROR_WANT_READ or e == SSL_ERROR_WANT_WRITE:
        return -2
      0

    proc tlsWrite*(conn: Connection, buf: pointer, count: int): int =
      ## SSL_write wrapper. Returns bytes written or -2 when the operation
      ## would block (caller buffers and waits for a Write event).
      if conn.ssl == nil: return -1
      let r = SSL_write(cast[SslPtr](conn.ssl), cast[cstring](buf), count.cint)
      if r > 0: return r
      let e = SSL_get_error(cast[SslPtr](conn.ssl), r)
      if e == SSL_ERROR_WANT_READ or e == SSL_ERROR_WANT_WRITE:
        return -2
      -1

    proc tlsFree*(conn: Connection) =
      ## Tear down the TLS session and release the SSL object.
      if conn.ssl != nil:
        discard SSL_shutdown(cast[SslPtr](conn.ssl))
        SSL_free(cast[SslPtr](conn.ssl))
        conn.ssl = nil
      conn.tlsState = TlsOff
  else:
    proc driveHandshake*(conn: Connection): bool = true
    proc tlsRead*(conn: Connection, buf: pointer, count: int): int = -1
    proc tlsWrite*(conn: Connection, buf: pointer, count: int): int = -1
    proc tlsFree*(conn: Connection) = discard

  proc watchWritable(conn: Connection) {.inline.} =
    ## Watch for writability so a partially-buffered write can flush.
    conn.loop.modify(conn.fd.int, {Read, Write})

  proc corkAndWatch(conn: Connection) {.inline.} =
    ## Enable TCP corking for the queued writes and watch for writability.
    if not conn.corked:
      setTcpCork(conn.fd, true)
      conn.corked = true
    conn.loop.modify(conn.fd.int, {Read, Write})

  proc send*(conn: Connection, data: openArray[byte]): int =
    if conn.state != Connected: return 0

    if conn.tlsState != TlsOff:
      # TLS: every byte must go through SSL_write. During the handshake (or when
      # a write is already pending) we simply queue — the flush happens once the
      # handshake completes / the socket becomes writable.
      if conn.tlsState == TlsHandshaking or conn.writeBuf.len > 0:
        let oldLen = conn.writeBuf.len
        conn.writeBuf.setLen(oldLen + data.len)
        copyMem(addr conn.writeBuf[oldLen], unsafeAddr data[0], data.len)
        return data.len
      let n = conn.tlsWrite(unsafeAddr data[0], data.len)
      if n == -2:
        conn.writeBuf.setLen(data.len)
        copyMem(addr conn.writeBuf[0], unsafeAddr data[0], data.len)
        conn.writePos = 0
        conn.watchWritable()
        return data.len
      if n < 0:
        conn.close()
        return -1
      if n < data.len:
        # SSL_write accepts at most one record (~16KB) per call; drain the rest
        # so we never buffer while the socket is still writable (edge-triggered).
        var pos = n
        while pos < data.len:
          let m = conn.tlsWrite(unsafeAddr data[pos], data.len - pos)
          if m == -2:
            break
          if m < 0:
            conn.close()
            return -1
          if m == 0:
            break
          pos += m
        if pos < data.len:
          let remaining = data.len - pos
          conn.writeBuf.setLen(remaining)
          copyMem(addr conn.writeBuf[0], unsafeAddr data[pos], remaining)
          conn.writePos = 0
          conn.watchWritable()
      return data.len

    if conn.writeBuf.len > 0:
      if not conn.queueWrite(data):
        return 0
      return data.len

    # Direct write, draining until EAGAIN. Edge-triggered Write events only fire
    # on a readiness transition, so we must never buffer the remainder while the
    # socket is still writable — otherwise no Write event will ever re-arm us
    # and the connection stalls.
    var pos = 0
    while pos < data.len:
      let n = sockSend(conn.fd, unsafeAddr data[pos], data.len - pos)
      if n < 0:
        if sockWouldBlock():
          break
        conn.close()
        return -1
      if n == 0:
        break  # defensive: send() returning 0 with len > 0 (peer closed)
      pos += n

    if pos < data.len:
      let remaining = data.len - pos
      conn.writeBuf.setLen(remaining)
      copyMem(addr conn.writeBuf[0], unsafeAddr data[pos], remaining)
      conn.writePos = 0
      conn.corkAndWatch()

    return data.len

  proc send*(conn: Connection, data: string): int =
    conn.send(data.toOpenArrayByte(0, data.high))

  proc sendv*(conn: Connection,
              parts: openArray[tuple[data: ptr UncheckedArray[byte],
                                     len: int]]): int =
    if conn.state != Connected: return 0

    var totalLen = 0
    for part in parts:
      totalLen += part.len

    if totalLen == 0: return 0

    if conn.tlsState != TlsOff:
      # No writev over TLS: coalesce and send through SSL_write. The coalesce
      # buffer is bounded so an attacker-controlled response body reflected via
      # sendv cannot force an arbitrarily large allocation (reflection DoS);
      # oversized payloads stream through a bounded chunk buffer instead.
      const MaxTlsCoalesce = 1 shl 20  # 1 MB
      if totalLen <= MaxTlsCoalesce:
        conn.tlsCoalesce.setLen(totalLen)
        var pos = 0
        for part in parts:
          copyMem(addr conn.tlsCoalesce[pos], part.data, part.len)
          pos += part.len
        return conn.send(conn.tlsCoalesce)
      conn.tlsCoalesce.setLen(MaxTlsCoalesce)
      var pos = 0
      for part in parts:
        var off = 0
        while off < part.len:
          let n = min(part.len - off, conn.tlsCoalesce.len - pos)
          copyMem(addr conn.tlsCoalesce[pos],
                  cast[ptr UncheckedArray[byte]](cast[uint](part.data) + off.uint), n)
          pos += n
          off += n
          if pos == conn.tlsCoalesce.len:
            discard conn.send(conn.tlsCoalesce.toOpenArray(0, pos - 1))
            pos = 0
      if pos > 0:
        discard conn.send(conn.tlsCoalesce.toOpenArray(0, pos - 1))
      return totalLen

    if conn.writeBuf.len > 0:
      for part in parts:
        if part.len > 0:
          if not conn.queueWrite(part.data.toOpenArray(0, part.len - 1)):
            return 0
      return totalLen

    const MaxStackIovs = 128
    var stackIovs: array[MaxStackIovs, IOVec]
    var heapIovs: seq[IOVec]
    var iovBuf: ptr IOVec
    var iovLen: int

    template initIovec(base: ptr UncheckedArray[byte], ln: int): IOVec =
      when defined(windows):
        IOVec(iov_base: base, iov_len: ln)
      else:
        IOVec(iov_base: base, iov_len: ln.csize_t)

    if parts.len <= MaxStackIovs:
      iovBuf = addr stackIovs[0]
      iovLen = parts.len
      for i in 0 ..< parts.len:
        stackIovs[i] = initIovec(parts[i].data, parts[i].len)
    else:
      heapIovs = newSeq[IOVec](parts.len)
      iovBuf = addr heapIovs[0]
      iovLen = parts.len
      for i in 0 ..< parts.len:
        heapIovs[i] = initIovec(parts[i].data, parts[i].len)

    let n = sockWritev(conn.fd, iovBuf, iovLen)
    if n < 0:
      if sockWouldBlock():
        conn.writeBuf.setLen(totalLen)
        var pos = 0
        for part in parts:
          copyMem(addr conn.writeBuf[pos], part.data, part.len)
          pos += part.len
        conn.writePos = 0
        conn.corkAndWatch()
        return totalLen
      conn.close()
      return -1

    if n < totalLen:
      # Advance to the unsent region, then keep writing until EAGAIN.
      # Edge-triggered Write events only fire on a readiness transition, so the
      # remainder must never be buffered while the socket is still writable —
      # otherwise no Write event will re-arm us and the connection stalls.
      var skipParts = 0
      var partOff = 0
      var consumed = n
      while skipParts < parts.len and consumed > 0:
        let avail = parts[skipParts].len - partOff
        if consumed >= avail:
          consumed -= avail
          inc skipParts
          partOff = 0
        else:
          partOff += consumed
          consumed = 0
      var subStack: array[MaxStackIovs, IOVec]
      var subIovs: seq[IOVec]
      var sentTotal = n
      var blocked = false
      while sentTotal < totalLen:
        let remaining = parts.len - skipParts
        if remaining <= 0: break
        var subBuf: ptr IOVec
        if remaining <= MaxStackIovs:
          subBuf = addr subStack[0]
          for i in 0 ..< remaining:
            let p = skipParts + i
            subStack[i] = initIovec(
              cast[ptr UncheckedArray[byte]](
                cast[uint](parts[p].data) + (if i == 0: partOff.uint else: 0.uint)),
              parts[p].len - (if i == 0: partOff else: 0))
        else:
          subIovs.setLen(remaining)
          subBuf = addr subIovs[0]
          for i in 0 ..< remaining:
            let p = skipParts + i
            subIovs[i] = initIovec(
              cast[ptr UncheckedArray[byte]](
                cast[uint](parts[p].data) + (if i == 0: partOff.uint else: 0.uint)),
              parts[p].len - (if i == 0: partOff else: 0))
        let m = sockWritev(conn.fd, subBuf, remaining)
        if m < 0:
          if sockWouldBlock():
            blocked = true
            break
          conn.close()
          return -1
        if m == 0:
          blocked = true   # defensive: writev returning 0 with len > 0
          break
        sentTotal += m
        var rm = m
        while skipParts < parts.len and rm > 0:
          let avail = parts[skipParts].len - partOff
          if rm >= avail:
            rm -= avail
            inc skipParts
            partOff = 0
          else:
            partOff += rm
            rm = 0
      if blocked and sentTotal < totalLen:
        # Buffer the still-unsent remainder and wait for a Write event (the
        # socket is genuinely not writable now, so the transition will fire).
        let remaining = totalLen - sentTotal
        conn.writeBuf.setLen(remaining)
        var pos = 0
        var sp = skipParts
        var off = partOff
        while sp < parts.len:
          let take = parts[sp].len - off
          copyMem(addr conn.writeBuf[pos],
                  cast[ptr UncheckedArray[byte]](cast[uint](parts[sp].data) + off.uint), take)
          pos += take
          inc sp
          off = 0
        conn.writePos = 0
        conn.corkAndWatch()

    return totalLen

  proc shutdown*(conn: Connection) =
    if conn.state != Connected: return
    if conn.writeBuf.len > 0:
      discard conn.flushWriteBuffer()
    elif conn.corked:
      setTcpCork(conn.fd, false)
      conn.corked = false
    if conn.state != Connected: return
    conn.state = Closing
    sockShutdown(conn.fd, shutWrVal())

  proc closeAfterDrain*(conn: Connection) {.inline.} =
    if conn.state == Closed: return
    if conn.writeBuf.len == 0:
      when defined(linux):
        # Graceful close: send FIN via shutdown() and let the peer drain the
        # response before closing. An immediate SO_LINGER=0 RST on Linux
        # discards the peer's unread receive buffer, silently dropping
        # just-sent responses. The connection is reclaimed when the peer closes
        # (handleClientRead sees EOF) or by the timeout sweep.
        if conn.tlsState == TlsOff:
          conn.shutdown()
          conn.loop.modify(conn.fd.int, {Read})
        else:
          conn.close()
      else:
        # macOS/BSD/Windows: a graceful FIN close collapses `Connection: close`
        # throughput ~8x under a wrk-style load generator on macOS/kqueue (even
        # though well-behaved clients are unaffected). Use the fast SO_LINGER=0
        # RST close here; it does not drop just-sent responses on these
        # platforms the way it can on Linux.
        conn.close()
    else:
      conn.closeAfterFlush = true

  proc closeAndRelease*(conn: Connection) {.inline.} =
    conn.close()
    if conn.readBuf != nil:
      releaseBuf(conn.loop, conn.readBuf)
      conn.readBuf = nil

  proc continueSendFile*(conn: Connection): bool =
    ## Resume an in-progress zero-copy file send when the socket becomes writable.
    ## Drains as much data as possible per edge-triggered Write event.
    ## Returns true when the send is complete (or error), false if more Write events needed.
    if conn.sendFileFd < 0: return true
    # Flush any buffered headers before sending file content
    if conn.writeBuf.len > 0:
      discard conn.flushWriteBuffer()
      if conn.writeBuf.len > 0:
        return false
    # Drain sendfile until EAGAIN (edge-triggered: send all we can per event)
    while conn.sendFileFd >= 0:
      if conn.sendFileRemain <= 0:
        closeFile(conn.sendFileFd)
        conn.sendFileFd = -1
        break
      let n = sendFileChunk(conn.fd, conn.sendFileFd, conn.sendFileOff, conn.sendFileRemain)
      if n < 0: closeFile(conn.sendFileFd); conn.sendFileFd = -1; return true
      if n == 0: return false  # ← triggered by remaining==0, treated as EAGAIN
      # conn.sendFileFd is NEVER cleared on success
    
    # All file data sent; flush any remaining headers
    if conn.writeBuf.len > 0:
      discard conn.flushWriteBuffer()
      if conn.writeBuf.len > 0:
        return false
    if conn.closeAfterFlush:
      conn.close()
    return true

  {.pop.}
  proc acquireConnection(server: TcpServer, fd: SocketHandle): Connection =
    if server.connPool.len > 0:
      result = server.connPool.pop()
      result.fd = fd
      result.sendFileFd = -1
      result.loop = server.loop
      result.server = server
      result.state = Connected
      result.ssl = nil
      result.tlsState = TlsOff
    else:
      result = Connection(
        fd:        fd,
        loop:      server.loop,
        server:    server,
        state:     Connected,
        sendFileFd: -1,
        readBuf:   acquireBuf(server.loop),
        readBufLen: DefaultBufSize,
      )

  proc releaseConnection(server: TcpServer, conn: Connection) =
    conn.state = Closed
    conn.fd = SocketHandle(-1)
    conn.corked = false
    conn.closeAfterFlush = false
    conn.sendFileFd = -1
    conn.sendFileOff = 0
    conn.sendFileRemain = 0
    conn.writeBuf.setLen(0)
    conn.writePos = 0
    conn.writeBuf.trimRetainedBuffer()
    conn.tlsCoalesce.setLen(0)
    conn.tlsCoalesce.trimRetainedBuffer()
    conn.clientIp = ""
    conn.ssl = nil
    conn.tlsState = TlsOff
    if server.connPool.len < MaxConnPoolSize:
      server.connPool.add(conn)
    else:
      if conn.readBuf != nil:
        releaseBuf(conn.loop, conn.readBuf)
        conn.readBuf = nil

  # ── TcpServer ────────────────────────────────────────────────────────────────

  proc handleClientRead(conn: Connection, onData: OnData, onClose: OnClose) =
    while conn.state == Connected or conn.state == Closing:
      if conn.tlsState == TlsHandshaking:
        # The handshake is driven from the event-loop callback, not here.
        return
      var n: int
      if conn.tlsState == TlsActive:
        n = conn.tlsRead(addr conn.readBuf[0], conn.readBufLen)
      else:
        when defined(windows):
          n = conn.loop.platform.getReadData(
            conn.fd.int, cast[ptr UncheckedArray[byte]](addr conn.readBuf[0]), conn.readBufLen)
        else:
          n = sockRecv(conn.fd, addr conn.readBuf[0], conn.readBufLen)
      if n > 0:
        if conn.state != Connected:
          # The write side was shut down (graceful close); discard any straggler
          # data and keep waiting for the peer's FIN.
          continue
        onData(conn, conn.readBuf.toOpenArray(0, n - 1))
        if conn.state != Connected:
          if onClose != nil: onClose(conn)
          return
        if conn.tlsState != TlsOff:
          # TLS was enabled during onData (STARTTLS-style upgrade); the
          # handshake is now driven from the event loop.
          return
      elif n == 0:
        conn.close()
        if onClose != nil: onClose(conn)
        return
      else:
        if n == -2:
          return
        when defined(windows):
          return
        else:
          if sockInterrupted():
            continue
          return

  proc acceptClients(server: TcpServer) =
    when defined(windows):
      # On Windows the listen socket is driven by AcceptEx (pure IOCP): accepted
      # sockets are queued by the platform backend and drained here. This matches
      # the epoll/kqueue methodology — no select() in the hot path.
      while true:
        let clientFd = server.loop.platform.takeAcceptedSocket(server.fd.int)
        if clientFd < 0: return
        var clientAddr {.noInit.}: Sockaddr_storage
        var addrLen: SockLen = sizeof(clientAddr).SockLen
        discard getpeername(clientFd.cint,
                            cast[ptr Sockaddr](addr clientAddr), addr addrLen)
        setNonBlocking(SocketHandle(clientFd))
        setTcpNoDelay(SocketHandle(clientFd))
        if server.maxConnections > 0 and server.fdConn.len >= server.maxConnections:
          sockClose(SocketHandle(clientFd))
          continue
        let conn = acquireConnection(server, SocketHandle(clientFd))
        conn.clientAddr = clientAddr
        if server.onAccept != nil:
          server.onAccept(conn)
        if conn.state == Closed:
          continue
        server.fdConn[clientFd.int] = conn
        conn.loop.register(clientFd.int, {Read}, edgeTriggered = true,
                           callback = server.sharedCb)
        conn.handleClientRead(server.onData, server.onClose)
        if conn.state == Closed:
          server.releaseConnection(conn)
          continue
    else:
      while true:
        var clientAddr {.noInit.}: Sockaddr_storage
        var addrLen: SockLen = sizeof(clientAddr).SockLen
        let clientFd = accept(server.fd,
                              cast[ptr Sockaddr](addr clientAddr),
                              addr addrLen)
        if clientFd.int >= 0:
          setNonBlocking(SocketHandle(clientFd))
          setTcpNoDelay(SocketHandle(clientFd))

        if clientFd.int < 0:
          if sockWouldBlock():
            return
          return
      
        if server.maxConnections > 0 and server.fdConn.len >= server.maxConnections:
          sockClose(clientFd)
          return
      
        let conn = acquireConnection(server, clientFd)
        conn.clientAddr = clientAddr

        if server.onAccept != nil:
          server.onAccept(conn)
        if conn.state == Closed:
          continue

        server.fdConn[clientFd.int] = conn
        conn.loop.register(clientFd.int, {Read}, edgeTriggered = true,
                           callback = server.sharedCb)
        conn.handleClientRead(server.onData, server.onClose)
        if conn.state == Closed:
          server.releaseConnection(conn)
          continue

  proc listen*(server: TcpServer, address: string, port: int) =
    let addrBuf = resolveAddr(address, port, SOCK_STREAM)
    let fd = socket(cast[ptr Sockaddr](addr addrBuf).sa_family.cint,
                    SOCK_STREAM, 0)
    if fd.cint < 0:
      raise newException(NetError, "socket() failed")

    setNonBlocking(fd)
    setReuseAddr(fd)
    setReusePort(fd)

    let sLen = getSockLen(addr addrBuf)
    if bindSocket(fd, cast[ptr Sockaddr](addr addrBuf), sLen) < 0:
      sockClose(fd)
      raise newException(NetError, "bind() failed")

    if listen(fd, SOMAXCONN) < 0:
      sockClose(fd)
      raise newException(NetError, "listen() failed")

    server.fd = fd

    server.loop.register(fd.int, {Read}) do (listenFd: int, ev: set[EventType]):
      server.acceptClients()

  when not defined(windows):
    proc listenUnix*(server: TcpServer, path: string; mode: int = 0o660) =
      let fd = socket(AF_UNIX.cint, SOCK_STREAM, 0)
      if fd.cint < 0:
        raise newException(NetError, "socket(AF_UNIX) failed")

      setNonBlocking(fd)

      proc c_unlink(path: cstring): cint {.importc: "unlink", header: "<unistd.h>".}
      discard c_unlink(path.cstring)

      var sockAddr: Sockaddr_un
      sockAddr.sun_family = AF_UNIX.uint8
      let pathLen = path.len
      if pathLen > UNIX_PATH_MAX:
        sockClose(fd)
        raise newException(NetError,
          "Unix socket path \"" & path & "\" exceeds max length (" & $UNIX_PATH_MAX & ")")
      copyMem(addr sockAddr.sun_path[0], path.cstring, pathLen + 1)

      let sLen = (sizeof(sockAddr.sun_family) + pathLen + 1).SockLen
      if bindSocket(fd, cast[ptr Sockaddr](addr sockAddr), sLen) < 0:
        sockClose(fd)
        raise newException(NetError, "bind(AF_UNIX) failed for " & path)

      proc c_chmod(path: cstring, mode: cint): cint {.importc: "chmod", header: "<sys/stat.h>".}
      discard c_chmod(path.cstring, mode.cint)

      if listen(fd, SOMAXCONN) < 0:
        sockClose(fd)
        raise newException(NetError, "listen() failed on AF_UNIX socket")

      server.fd = fd
      server.unixPath = path

      server.loop.register(fd.int, {Read}) do (listenFd: int, ev: set[EventType]):
        server.acceptClients()

  proc close*(server: TcpServer) =
    for conn in server.connPool:
      if conn.readBuf != nil:
        releaseBuf(conn.loop, conn.readBuf)
        conn.readBuf = nil
    server.connPool.setLen(0)
    if server.fd.int >= 0:
      server.loop.unregister(server.fd.int)
      sockClose(server.fd)
      server.fd = SocketHandle(-1)
    if server.unixPath.len > 0:
      when not defined(windows):
        proc c_unlink(path: cstring): cint {.importc: "unlink", header: "<unistd.h>".}
        discard c_unlink(server.unixPath.cstring)
      server.unixPath.setLen(0)

  proc injectFd*(server: TcpServer, clientFd: SocketHandle) =
    let conn = acquireConnection(server, clientFd)

    if server.onAccept != nil:
      server.onAccept(conn)
    if conn.state == Closed:
      return

    server.fdConn[clientFd.int] = conn
    conn.loop.register(clientFd.int, {Read}, edgeTriggered = true,
                       callback = server.sharedCb)

  proc newTcpServer*(loop: Loop,
                     onData: OnData,
                     onAccept: OnAccept = nil,
                     onClose: OnClose = nil): TcpServer =
    let srv {.cursor.} = TcpServer(
      fd:       SocketHandle(-1),
      loop:     loop,
      onAccept: onAccept,
      onData:   onData,
      onClose:  onClose,
      connPool: @[],
      fdConn:   initTable[int, Connection](64),
      sharedCb: nil,
      unixPath: "",
      maxConnections: 0,
    )
    # Create one shared callback for all connections — no closure allocation per accept
    srv.sharedCb = proc(fd: int, ev: set[EventType]) {.closure.} =
      let conn = srv.fdConn.getOrDefault(fd)
      if conn == nil: return
      if Error in ev:
        conn.close()
        if srv.onClose != nil: srv.onClose(conn)
        srv.releaseConnection(conn)
        return
      if conn.tlsState == TlsHandshaking:
        # Progress the TLS handshake on any I/O; return until it completes.
        if not conn.driveHandshake():
          return
      if Write in ev:
        if conn.sendFileFd >= 0:
          if conn.continueSendFile():
            if conn.state == Connected:
              conn.loop.modify(fd, {Read})
              conn.handleClientRead(srv.onData, srv.onClose)
        elif conn.flushWriteBuffer():
          if conn.closeAfterFlush:
            conn.close()
            if srv.onClose != nil: srv.onClose(conn)
            srv.releaseConnection(conn)
            return
          if conn.state == Connected:
            conn.loop.modify(fd, {Read})
      if (Read in ev or Hup in ev) and conn.sendFileFd < 0:
        conn.handleClientRead(srv.onData, srv.onClose)
      if Hup in ev and conn.state == Connected:
        conn.close()
        if srv.onClose != nil: srv.onClose(conn)
      if conn.state == Closed:
        srv.releaseConnection(conn)
    srv

  # ── Client connect ───────────────────────────────────────────────────────────

  proc connect*(loop: Loop, address: string, port: int,
                onConnect: proc(conn: Connection) {.closure.},
                onData: OnData,
                onClose: OnClose = nil,
                onError: OnError = nil) =
    ## Non-blocking TCP connect. DNS resolution is performed asynchronously on
    ## the loop (see net/dns), so a slow resolver never blocks the event loop.
    ## When a host resolves to multiple addresses they are tried in order —
    ## if one is unreachable the next is attempted before `onError` fires.
    ## `onError` reports DNS / socket() / connect() failures; when nil these are
    ## dropped silently (matching the existing non-blocking connect failure path).
    resolveAddrAsync(loop, address, port, SOCK_STREAM,
      proc(addrs: seq[Sockaddr_storage]; err: string) =
        if err.len > 0:
          if onError != nil:
            onError(err)
          return
        if addrs.len == 0:
          if onError != nil:
            onError("connect: no addresses resolved for " & address)
          return

        var tryIdx = 0
        var connTimer: TimerId = TimerId(0)
        proc attemptNext() {.closure.} =
          if connTimer != TimerId(0):
            loop.cancelTimer(connTimer)
            connTimer = TimerId(0)
          if tryIdx >= addrs.len:
            if onError != nil:
              onError("connect() failed on all resolved addresses for " & address)
            return
          let addrBuf = addrs[tryIdx]
          inc tryIdx

          let fd = socket(cast[ptr Sockaddr](addr addrBuf).sa_family.cint,
                          SOCK_STREAM, 0)
          if fd.cint < 0:
            if onError != nil:
              onError("socket() failed")
            return

          setNonBlocking(fd)
          setTcpNoDelay(fd)

          let conn = Connection(
            fd:        fd,
            loop:      loop,
            state:     Connecting,
            readBuf:   acquireBuf(loop),
            readBufLen: DefaultBufSize,
          )

          let sLen = getSockLen(addr addrBuf)
          let ret = connect(fd, cast[ptr Sockaddr](addr addrBuf), sLen)
          if ret < 0 and not sockInProgress():
            conn.closeAndRelease()
            attemptNext()
            return

          if ret == 0:
            conn.state = Connected
            conn.loop.register(fd.int, {Read}) do (rfd: int, ev: set[EventType]):
              if Error in ev:
                conn.closeAndRelease()
                if onClose != nil: onClose(conn)
                return
              if conn.tlsState == TlsHandshaking:
                if not conn.driveHandshake():
                  return
              if Write in ev:
                if conn.flushWriteBuffer():
                  if conn.closeAfterFlush:
                    conn.closeAndRelease()
                    if onClose != nil: onClose(conn)
                    return
                  if conn.state == Connected:
                    conn.loop.modify(rfd, {Read})
              if Read in ev or Hup in ev:
                conn.handleClientRead(onData, onClose)
              if Hup in ev and conn.state == Connected:
                conn.closeAndRelease()
                if onClose != nil: onClose(conn)
            onConnect(conn)
            if conn.state == Closed: return
          else:
            conn.loop.register(fd.int, {Write}) do (wfd: int, ev: set[EventType]):
              if connTimer != TimerId(0):
                loop.cancelTimer(connTimer)
                connTimer = TimerId(0)
              conn.loop.unregister(wfd)
              if conn.fd.int != wfd:
                # The watcher fired for a stale event after this connection's fd
                # was closed and the number reused by another socket. Never act
                # on an fd this connection no longer owns.
                return
              # kqueue reports a refused connect as EV_ERROR (mapped to the Error
              # event here) with the errno in the kevent data — SO_ERROR may read
              # 0 on that path, so a refused address must be detected from the
              # event set too (otherwise we misdetect success and never fall
              # back to the next address).
              if Error in ev:
                conn.closeAndRelease()
                attemptNext()
                return
              var err: cint = 0
              var errLen: SockLen = sizeof(err).SockLen
              discard getsockopt(fd, SOL_SOCKET, SO_ERROR, addr err, addr errLen)
              if err != 0:
                conn.closeAndRelease()
                attemptNext()
                return

              conn.state = Connected
              setTcpNoDelay(SocketHandle(wfd))
              conn.loop.register(wfd, {Read}) do (rfd: int, ev: set[EventType]):
                if Error in ev:
                  conn.closeAndRelease()
                  if onClose != nil: onClose(conn)
                  return
                if conn.tlsState == TlsHandshaking:
                  if not conn.driveHandshake():
                    return
                if Write in ev:
                  if conn.flushWriteBuffer():
                    if conn.closeAfterFlush:
                      conn.closeAndRelease()
                      if onClose != nil: onClose(conn)
                      return
                    if conn.state == Connected:
                      conn.loop.modify(rfd, {Read})
                if Read in ev or Hup in ev:
                  conn.handleClientRead(onData, onClose)
                if Hup in ev and conn.state == Connected:
                  conn.closeAndRelease()
                  if onClose != nil: onClose(conn)
              onConnect(conn)
              if conn.state == Closed: return
            # The connect may never complete (no writable event on some platforms);
            # fall back to the next address after a timeout instead of hanging.
            connTimer = loop.addTimer(ConnectTimeoutMs) do (id: int):
              conn.closeAndRelease()
              attemptNext()
        attemptNext()
    )

  when not defined(windows):
    proc connectUnix*(loop: Loop; path: string;
                      onConnect: proc(conn: Connection) {.closure.};
                      onData: OnData;
                      onClose: OnClose = nil) =
      let fd = socket(AF_UNIX.cint, SOCK_STREAM, 0)
      if fd.cint < 0:
        raise newException(NetError, "socket(AF_UNIX) failed")

      setNonBlocking(fd)

      let conn = Connection(
        fd:        fd,
        loop:      loop,
        state:     Connecting,
        readBuf:   acquireBuf(loop),
        readBufLen: DefaultBufSize,
      )

      var sockAddr: Sockaddr_un
      sockAddr.sun_family = AF_UNIX.uint8
      let pathLen = path.len
      if pathLen > UNIX_PATH_MAX:
        conn.closeAndRelease()
        raise newException(NetError,
          "Unix socket path \"" & path & "\" exceeds max length (" & $UNIX_PATH_MAX & ")")
      copyMem(addr sockAddr.sun_path[0], path.cstring, pathLen + 1)
      let sLen = (sizeof(sockAddr.sun_family) + pathLen + 1).SockLen

      let ret = connect(fd, cast[ptr Sockaddr](addr sockAddr), sLen)
      if ret < 0 and not sockInProgress():
        conn.closeAndRelease()
        raise newException(NetError, "connect(AF_UNIX) failed for " & path)

      if ret == 0:
        conn.state = Connected
        conn.loop.register(fd.int, {Read}) do (rfd: int, ev: set[EventType]):
          if Error in ev:
            conn.closeAndRelease()
            if onClose != nil: onClose(conn)
            return
          if conn.tlsState == TlsHandshaking:
            if not conn.driveHandshake():
              return
          if Write in ev:
            if conn.flushWriteBuffer():
              if conn.closeAfterFlush:
                conn.closeAndRelease()
                if onClose != nil: onClose(conn)
                return
              if conn.state == Connected:
                conn.loop.modify(rfd, {Read})
          if Read in ev or Hup in ev:
            conn.handleClientRead(onData, onClose)
          if Hup in ev and conn.state == Connected:
            conn.closeAndRelease()
            if onClose != nil: onClose(conn)
        onConnect(conn)
        if conn.state == Closed: return
      else:
        conn.loop.register(fd.int, {Write}) do (wfd: int, ev: set[EventType]):
          conn.loop.unregister(wfd)
          var err: cint = 0
          var errLen: SockLen = sizeof(err).SockLen
          discard getsockopt(fd, SOL_SOCKET, SO_ERROR, addr err, addr errLen)
          if err != 0:
            conn.closeAndRelease()
            return

          conn.state = Connected
          conn.loop.register(wfd, {Read}) do (rfd: int, ev: set[EventType]):
            if Error in ev:
              conn.closeAndRelease()
              if onClose != nil: onClose(conn)
              return
            if conn.tlsState == TlsHandshaking:
              if not conn.driveHandshake():
                return
            if Write in ev:
              if conn.flushWriteBuffer():
                if conn.closeAfterFlush:
                  conn.closeAndRelease()
                  if onClose != nil: onClose(conn)
                  return
                if conn.state == Connected:
                  conn.loop.modify(rfd, {Read})
            if Read in ev or Hup in ev:
              conn.handleClientRead(onData, onClose)
            if Hup in ev and conn.state == Connected:
              conn.closeAndRelease()
              if onClose != nil: onClose(conn)
          onConnect(conn)
          if conn.state == Closed: return
