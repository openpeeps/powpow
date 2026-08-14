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
      sfSpliceRead     # SPLICE(file → pipe) in flight
      sfSpliceSend     # SPLICE(pipe → socket) in flight
      # NOTE: there is no IORING_OP_SENDFILE. Zero-copy file→socket transfers
      # use IORING_OP_SPLICE (file→pipe→socket); the READ + SEND chunk pump is
      # the fallback.

  const
    MaxEagainRetries = 1
    AcceptBatch = 8   # outstanding one-shot IORING_OP_ACCEPT ops per listener
    AcceptReserveSlots = 2   # SQ slots kept free for the timeout + re-arms
    F_SETPIPE_SZ = 1031   # fcntl(2): resize a pipe buffer (linux/fcntl.h)
    SendZcThreshold = when defined(powpowSendZcThreshold): powpowSendZcThreshold else: 64 * 1024
    SpliceChunkSize = when defined(powpowSpliceChunk): powpowSpliceChunk else: 1_048_576
      ## Bytes moved per file→pipe SPLICE. Kernel-to-kernel, so unlike the
      ## READ + SEND fallback there is no user-space buffer — a large chunk
      ## (and a matching pipe) keeps the number of ops/completions low and
      ## approaches sendfile(2) throughput.
      ## Payloads at or above this size are sent with IORING_OP_SEND_ZC (below it
      ## the page-pinning cost exceeds the copy the zero-copy send avoids).

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
      fixedFd:        bool   # fd is registered in the loop's fixed-file table
      tlsOutBuf:      seq[byte]   # encrypted output drained from the SSL write BIO
      tlsOutPos:      int
      tlsWriteToken:  uint64
      # Cached per-op completion callbacks, allocated once per connection
      # instead of once per submitted op (the old inline-closure style put a
      # fresh GC allocation on every RECV/SEND/TLS-SEND/README/SEND path).
      readCb:         OpCallback
      writeCb:        OpCallback
      tlsWriteCb:     OpCallback
      sendFileReadCb: OpCallback
      spliceCb:       OpCallback
      shutdownCb:     OpCallback
      bufferReadCb:   OpCallback
      # Per-connection pipe for zero-copy SPLICE file transfers. A shared loop
      # pipe is not safe: concurrent transfers would interleave in the FIFO and
      # splice the wrong peer's bytes to a socket.
      splicePipe:     array[2, cint]   # [0] = read end, [1] = write end
      splicePipeOk:   bool
      spliceChunk:    int    # bytes currently in the pipe awaiting socket send
      spliceSent:     int    # bytes of the current chunk already sent to socket
      # Coalesce buffer for writes arriving while a SEND op references
      # writeBuf/tlsOutBuf (appending to the in-flight seq could reallocate the
      # very memory the kernel SEND is reading). Merged once the op drains.
      pendingBuf:     seq[byte]
      tlsPending:     seq[byte]
      # Zero-copy send in flight: writeBuf's pages are pinned by the kernel until
      # the IORING_CQE_F_NOTIF completion arrives, so writeBuf must not be
      # touched/reused before it does. Until then, new writes coalesce into
      # pendingBuf exactly like they do while a plain SEND op is in flight.
      zcPending:      bool
      # Retired connection: closed while an op was still in flight. Its read
      # buffer / send chunk stay alive until every outstanding op settles, so
      # the kernel can never write into a re-pooled buffer.
      retiring:       bool
      retireTokens:   array[4, uint64]
      retireCount:    int

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
      acceptTokens: array[AcceptBatch, uint64]
      acceptAddrs:  array[AcceptBatch, Sockaddr_storage]
      acceptAddrLens: array[AcceptBatch, SockLen]
      acceptCb:     OpCallback
      acceptMultishot: bool    # a single IORING_OP_ACCEPT multishot op is armed
      acceptMultishotFailed: bool  # kernel rejected multishot; use the batch
      fixedFd:      bool   # listener fd is registered in the loop's fixed-file table
    else:
      sharedCb:  FdCallback

proc newConnection*(fd: SocketHandle, loop: Loop, server: TcpServer,
                    readBuf: ptr UncheckedArray[byte], readBufLen: int): Connection {.inline.} =
  result = Connection(
    fd: fd, loop: loop, server: server, state: Closed,
    readBuf: readBuf, readBufLen: readBufLen,
    sendFileFd: -1)
  when iouEnabled:
    result.splicePipe = [-1.cint, -1.cint]

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
  proc beginRetire(conn: Connection) {.gcsafe.}
  proc retireSettled(conn: Connection, token: uint64): bool {.gcsafe.}
  proc retireFinalize(conn: Connection) {.gcsafe.}
  proc closeSplicePipe(conn: Connection) {.gcsafe.}

  # ── Connection ───────────────────────────────────────────────────────────────

  proc finishClose(conn: Connection) {.gcsafe.} =
    ## Actual socket teardown, extracted so `close` can defer it until pending
    ## writes (in-flight SEND ops) have delivered their bytes.
    if conn.fd.int >= 0:
      setLinger0(conn.fd)
      conn.loop.unregisterFd(conn.fd.int)
      if conn.fixedFd:
        conn.loop.unregisterFixedFd(conn.fd.int)
        conn.fixedFd = false
      if conn.ssl != nil:
        conn.tlsFree()
      sockClose(conn.fd)
      conn.fd = SocketHandle(-1)
    conn.closeSplicePipe()
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
    # Cancel in-flight ops. Any op that can still write into a connection buffer
    # (RECV → readBuf, sendfile READ → sendChunk, CONNECT → connectAddr, SEND →
    # writeBuf) begins the retire path: the connection and its buffers stay
    # alive until every such op settles, so the kernel can never write into a
    # re-pooled buffer after the fd number has been reused.
    if conn.readToken != 0:
      conn.loop.cancelOp(conn.readToken)
    if conn.connectToken != 0:
      conn.loop.cancelOp(conn.connectToken)
    conn.loop.clearTakeoverCb(conn.fd.int)
    if conn.sendFileToken != 0:
      conn.loop.cancelOp(conn.sendFileToken)
    conn.beginRetire()
    if conn.writeToken != 0 or conn.writeBuf.len > 0 or
       conn.pendingBuf.len > 0 or
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

  proc beginRetire(conn: Connection) {.gcsafe.} =
    ## Hold the connection (and the buffers its ops may still write) until every
    ## in-flight op settles. A retired connection is never returned to the pool;
    ## retireFinalize releases its read buffer once all ops have settled.
    ##
    ## Only ops that write into buffers released at close time are tracked: RECV
    ## (→ readBuf) and the sendfile READ (→ sendChunk). Read-only ops (SEND,
    ## CONNECT) keep the connection object — and thus writeBuf/connectAddr —
    ## alive via their completion callbacks until they settle.
    if conn.retiring:
      return
    if conn.readToken == 0 and conn.sendFileToken == 0:
      return
    conn.retiring = true
    conn.retireCount = 0
    if conn.readToken != 0:
      conn.retireTokens[conn.retireCount] = conn.readToken
      inc conn.retireCount
    if conn.sendFileToken != 0:
      conn.retireTokens[conn.retireCount] = conn.sendFileToken
      inc conn.retireCount

  proc retireSettled(conn: Connection, token: uint64): bool {.gcsafe.} =
    ## Mark one retired op's completion as received. Returns true when every
    ## retired op has settled (the connection has been finalized).
    if not conn.retiring:
      return false
    for i in 0 ..< conn.retireCount:
      if conn.retireTokens[i] == token:
        conn.retireTokens[i] = conn.retireTokens[conn.retireCount - 1]
        dec conn.retireCount
        break
    if conn.retireCount == 0:
      conn.retireFinalize()
      true
    else:
      false

  proc retireFinalize(conn: Connection) {.gcsafe.} =
    ## Every in-flight op has settled, so the kernel can no longer write into
    ## conn's read buffer: release it. The connection object is left otherwise
    ## intact — no external references remain (fdConn entry deleted, session
    ## removed, op callbacks consumed), so it is collected by the GC.
    conn.retiring = false
    conn.retireCount = 0
    if conn.readBuf != nil:
      releaseBuf(conn.loop, conn.readBuf)
      conn.readBuf = nil
    conn.sendChunk.setLen(0)

  proc queueWrite(conn: Connection, data: openArray[byte]): bool {.gcsafe.} =
    if data.len == 0:
      return true
    # A SEND op references writeBuf[writePos .. ^1]; appending to it could
    # reallocate the buffer the kernel is reading (use-after-free). The same
    # holds while a SEND_ZC op is in flight and writeBuf's pages are pinned.
    # Coalesce into pendingBuf instead and promote it once the in-flight op
    # drains (see onWriteComplete).
    if conn.writeToken != 0 or conn.zcPending:
      if conn.writeBuf.len + conn.pendingBuf.len + data.len > MaxWriteBufferSize:
        conn.close()
        return false
      let oldLen = conn.pendingBuf.len
      conn.pendingBuf.setLen(oldLen + data.len)
      copyMem(addr conn.pendingBuf[oldLen], unsafeAddr data[0], data.len)
    else:
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
    if conn.retireSettled(token):
      # Retired connection: this was the last in-flight op; the read buffer has
      # been released and the connection must not be touched further.
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

  when defined(powpowBufferSelect):
    proc onBufferReadComplete(conn: Connection, token: uint64, res: int32, flags: uint32) =
      ## Completion for a multishot RECV over the shared provided-buffer group.
      ## The RECV stays armed (IORING_CQE_F_MORE) across reads; each completion
      ## carries the selected buffer id in the upper 16 bits of cqe.flags (older
      ## kernels: res' upper 16 bits). The buffer is recycled right after the
      ## data is delivered so the kernel can select it for the next event
      ## without a re-arm.
      if conn.readToken != token:
        # Stale completion from a previous lifecycle (pooled connection reused):
        # any selected group buffer must still be recycled or the group leaks.
        if res > 0:
          let bufId =
            if (flags and 0xFFFF0000'u32) != 0: (flags shr 16).int
            else: (res shr 16).int
          conn.loop.recycleReadBuf(bufId)
        return
      if (flags and uring.IORING_CQE_F_MORE) == 0:
        conn.readToken = 0
        if conn.retireSettled(token):
          return
      if conn.state == Closed or conn.state == Connecting:
        # A buffer selected by a stale/closed lifecycle must still be recycled —
        # it is removed from the group until PROVIDE_BUFFERS returns it.
        if res > 0:
          let bufId =
            if (flags and 0xFFFF0000'u32) != 0: (flags shr 16).int
            else: (res shr 16).int
          conn.loop.recycleReadBuf(bufId)
        return
      if res == -ECANCELED:
        return
      if res == -ENOBUFS:
        # The group is momentarily empty: every buffer is held by completions
        # still in this reap batch, which recycle each as they are processed.
        conn.loop.deferCall(proc() =
          if conn.state != Closed and conn.readToken == 0:
            conn.armRead())
        return
      if res < 0:
        if res == -ECONNRESET or res == -ECONNABORTED or res == -ENOTCONN or
           res == -EPIPE or res == -ECONNREFUSED:
          conn.close()
          conn.fireClose()
          return
        # EAGAIN / spurious: keep waiting; re-arm only if the op ended.
        if conn.readToken == 0:
          conn.armRead()
        return
      if res == 0:
        # EOF (peer closed or shutdown)
        conn.close()
        conn.fireClose()
        return
      let bytes = res and 0xFFFF
      let bufId =
        if (flags and 0xFFFF0000'u32) != 0: (flags shr 16).int
        else: (res shr 16).int
      let buf = conn.loop.readBufAt(bufId)
      if conn.state != Connected:
        # write side shut down (graceful close): discard stragglers, wait for FIN
        conn.loop.recycleReadBuf(bufId)
        if conn.readToken == 0:
          conn.armRead()
        return
      if conn.tlsState != TlsOff:
        # STARTTLS-style upgrade: the multishot RECV is already armed and keeps
        # reading; feed the ciphertext to SSL instead of the plaintext path.
        conn.handleTlsData(buf, bytes)
        conn.afterData()
        conn.loop.recycleReadBuf(bufId)
        if conn.state == Closed: return
        if conn.readToken == 0:
          conn.armRead()
        return
      if conn.onDataCb != nil:
        conn.onDataCb(conn, buf.toOpenArray(0, bytes - 1))
      elif conn.server != nil and conn.server.onData != nil:
        conn.server.onData(conn, buf.toOpenArray(0, bytes - 1))
      conn.afterData()
      conn.loop.recycleReadBuf(bufId)
      if conn.state == Closed:
        return
      if conn.readToken == 0:
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
    when defined(powpowBufferSelect):
      if conn.tlsState == TlsOff and conn.loop.bufferSelectEnabled():
        # Multishot RECV over the shared provided-buffer group: one submission
        # stays armed for the connection's lifetime. Each completion delivers a
        # group buffer that is recycled right after delivery, so reads need no
        # per-read re-arm and no per-connection read buffer.
        let sqe = conn.loop.getOpSqe()
        if sqe == nil:
          conn.loop.deferCall(proc() =
            if conn.state != Closed:
              conn.armRead())
          return
        sqe.opcode = IORING_OP_RECV.uint8
        sqe.fd = conn.fd.int32
        sqe.flags = IOSQE_BUFFER_SELECT.uint8
        sqe.ioprio = IORING_RECV_MULTISHOT.uint16
        sqe.setBufGroup(ReadBufBgid)
        conn.readToken = conn.loop.commitOp(sqe, conn.bufferReadCb)
        return
    let sqe = conn.loop.getOpSqe()
    if sqe == nil:
      conn.loop.deferCall(proc() =
        if conn.state != Closed:
          conn.armRead())
      return
    sqe.opcode = IORING_OP_RECV.uint8
    sqe.fd = conn.fd.int32
    if conn.fixedFd:
      sqe.flags = IOSQE_FIXED_FILE.uint8
    sqe.paddr = cast[uint64](conn.readBuf)
    sqe.len = conn.readBufLen.uint32
    conn.readToken = conn.loop.commitOp(sqe, conn.readCb)

  # ── Write path ───────────────────────────────────────────────────────────────

  proc onShutdownComplete(conn: Connection, token: uint64, res: int32, flags: uint32) =
    ## Fire-and-forget IORING_OP_SHUTDOWN completion. On failure (e.g. an old
    ## kernel without the opcode) fall back to the syscall so graceful close
    ## still delivers the FIN.
    if res < 0 and conn.state != Closed and conn.fd.int >= 0:
      sockShutdown(conn.fd, shutWrVal())

  proc ringShutdown(conn: Connection) =
    ## Gracefully shut down the write side with IORING_OP_SHUTDOWN (the FIN is
    ## sent when the op completes; the state machine does not wait on it). Falls
    ## back to the syscall when the ring has no slot or the op is unsupported.
    ## Opt-in via `-d:powpowShutdownOp`: the extra op + completion per graceful
    ## close costs ~40% in connection:close throughput on the WSL2 6.18 box
    ## (33k → 20k req/s), so the synchronous syscall stays the default.
    if conn.fd.int < 0:
      return
    when defined(powpowShutdownOp):
      if conn.loop.supportsOp(uring.IORING_OP_SHUTDOWN):
        let sqe = conn.loop.getOpSqe()
        if sqe != nil:
          sqe.opcode = IORING_OP_SHUTDOWN.uint8
          sqe.fd = conn.fd.int32
          sqe.opFlags = shutWrVal().uint32
          discard conn.loop.commitOp(sqe, conn.shutdownCb)
          return
    sockShutdown(conn.fd, shutWrVal())

  proc writeDrained(conn: Connection) =
    ## writeBuf has been fully handed to the kernel and the kernel no longer
    ## references it (a plain SEND completion, or the SEND_ZC NOTIF). Reset it,
    ## promote any coalesced pending writes, and drive the post-write state
    ## machine (close-after-flush / shutdown-after-send / read re-arm).
    conn.writeBuf.setLen(0)
    conn.writePos = 0
    if conn.pendingBuf.len > 0:
      # Writes queued while a SEND was in flight: promote them (shared data
      # pointer, so nothing is copied) and keep the write pump going.
      conn.writeBuf = conn.pendingBuf
      conn.pendingBuf.setLen(0)
      if not conn.corked:
        setTcpCork(conn.fd, true)
        conn.corked = true
      conn.armWrite()
      return
    if conn.corked:
      setTcpCork(conn.fd, false)
      conn.corked = false
    if conn.closePending:
      conn.closePending = false
      conn.finishClose()
      if conn.server != nil:
        conn.server.releaseConnection(conn)
      elif not conn.retiring:
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
      conn.ringShutdown()
    else:
      conn.armRead()

  proc onWriteComplete(conn: Connection, token: uint64, res: int32, flags: uint32) =
    if conn.writeToken != token:
      return
    if (flags and uring.IORING_CQE_F_NOTIF) != 0:
      # Zero-copy notification: the kernel is done with writeBuf's pages. The
      # token was kept set since the SEND_ZC data completion, so nothing reused
      # the buffer in between; settle it now.
      conn.writeToken = 0
      conn.zcPending = false
      if conn.writePos >= conn.writeBuf.len:
        conn.writeDrained()
      else:
        # A partial ZC send left a remainder in writeBuf; continue it now that
        # the pages are safe to reference again.
        conn.armWrite()
      return
    if conn.sendState == sfSending:
      # Completion of a sendfile chunk SEND (the writeToken slot is shared with
      # the regular write pump; the state machine tells the two apart).
      conn.writeToken = 0
      if conn.state == Closed:
        # Connection closed while a chunk SEND was in flight: finish the
        # deferred teardown now that the op has settled.
        if conn.closePending:
          conn.closePending = false
          conn.finishClose()
        return
      if res <= 0:
        conn.close()
        conn.fireClose()
        return
      conn.sendFileOff += res.int64
      conn.sendFileRemain -= res.int64
      conn.sendState = sfIdle
      conn.pumpSendFile()
      return
    if conn.state != Connected and conn.state != Closing and not conn.closePending:
      conn.writeToken = 0
      return
    if res == -ECANCELED:
      conn.writeToken = 0
      return
    if res < 0:
      let wasZc = conn.zcPending
      conn.writeToken = 0
      conn.zcPending = false
      if wasZc and (res == -EINVAL or res == -EOPNOTSUPP):
        # Kernel does not support SEND_ZC; disable it for the loop and retry the
        # same buffer as a plain SEND.
        conn.loop.zcFailed = true
        conn.armWrite()
        return
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
    if (flags and uring.IORING_CQE_F_MORE) != 0:
      # SEND_ZC data completion: every byte was queued to the kernel, but its
      # pages stay pinned until the IORING_CQE_F_NOTIF completion. Keep the
      # write token set so armWrite/send coalesce into pendingBuf and never
      # reuse writeBuf; the NOTIF settles it.
      conn.zcPending = true
      return
    conn.writeToken = 0
    if conn.writePos >= conn.writeBuf.len:
      conn.writeDrained()
    else:
      conn.armWrite()

  proc armWrite(conn: Connection) {.gcsafe.} =
    if conn.writeToken != 0 or conn.writeBuf.len == 0 or conn.zcPending:
      return
    if conn.tlsState != TlsOff:
      # TLS conns never send raw plaintext; ciphertext goes through armTlsWrite.
      return
    if conn.state != Connected and conn.state != Closing and not conn.closePending:
      return
    let start = conn.writePos
    let remaining = conn.writeBuf.len - start
    let sqe = conn.loop.getOpSqe()
    if sqe == nil:
      conn.loop.deferCall(proc() =
        if conn.state != Closed:
          conn.armWrite())
      return
    if conn.loop.zcEnabled() and remaining >= SendZcThreshold:
      # Zero-copy send: the kernel pins writeBuf's pages and reports completion
      # in two CQEs — a data completion (IORING_CQE_F_MORE) and, once the pages
      # may be reused, a notification (IORING_CQE_F_NOTIF). writeToken stays set
      # until the NOTIF so nothing touches writeBuf in between.
      sqe.opcode = IORING_OP_SEND_ZC.uint8
      sqe.fd = conn.fd.int32
      if conn.fixedFd:
        sqe.flags = IOSQE_FIXED_FILE.uint8
      sqe.paddr = cast[uint64](addr conn.writeBuf[start])
      sqe.len = remaining.uint32
      conn.writeToken = conn.loop.commitOp(sqe, conn.writeCb)
      conn.zcPending = true
      return
    sqe.opcode = IORING_OP_SEND.uint8
    sqe.fd = conn.fd.int32
    if conn.fixedFd:
      sqe.flags = IOSQE_FIXED_FILE.uint8
    sqe.paddr = cast[uint64](addr conn.writeBuf[start])
    sqe.len = remaining.uint32
    conn.writeToken = conn.loop.commitOp(sqe, conn.writeCb)

  # ── sendfile (READ + SEND pump) ──────────────────────────────────────────────

  proc sendFileSendChunk(conn: Connection, n: int) =
    conn.sendState = sfSending
    conn.writeToken = conn.loop.submitOp(proc(sqe: ptr IoUringSqe) =
        sqe.opcode = IORING_OP_SEND.uint8
        sqe.fd = conn.fd.int32
        if conn.fixedFd:
          sqe.flags = IOSQE_FIXED_FILE.uint8
        sqe.paddr = cast[uint64](addr conn.sendChunk[0])
        sqe.len = n.uint32
      , conn.writeCb)

  proc onSendFileReadComplete(conn: Connection, token: uint64, res: int32, flags: uint32) =
    if conn.sendFileToken != token:
      return
    if conn.retireSettled(token):
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
    conn.sendFileSendChunk(res)

  # ── sendfile zero-copy via IORING_OP_SPLICE (file → pipe → socket) ──────────
  # The pipe is per-connection so concurrent transfers never interleave in a
  # shared FIFO. File offset advances on the file→pipe leg; the pipe→socket leg
  # retries on -EAGAIN (socket send buffer full) via the writability watcher.

  proc closeSplicePipe(conn: Connection) {.gcsafe.} =
    ## Tear down the per-connection splice pipe. Guarded by `splicePipeOk`: a
    ## fresh Connection's `splicePipe` defaults to [0, 0] (zeroed memory), so
    ## without the guard this would close fd 0/1 (the wake eventfd, stdin) and
    ## corrupt the loop under connection churn.
    if not conn.splicePipeOk:
      conn.splicePipe = [-1.cint, -1.cint]
      return
    if conn.splicePipe[0] >= 0:
      discard posix.close(conn.splicePipe[0])
      discard posix.close(conn.splicePipe[1])
      conn.splicePipe = [-1.cint, -1.cint]
    conn.splicePipeOk = false

  proc ensureSplicePipe(conn: Connection): bool =
    if conn.splicePipeOk:
      return true
    var fds: array[2, cint]
    if pipe(fds) != 0:
      return false
    discard fcntl(fds[0], F_SETFL, O_NONBLOCK)
    discard fcntl(fds[1], F_SETFL, O_NONBLOCK)
    # Size the pipe to hold two chunks so a file→pipe fill never stalls on a
    # small pipe and the pipe→socket leg can drain a full chunk at a time.
    # (F_SETPIPE_SZ may be capped by /proc/sys/fs/pipe-max-size; on failure the
    # pipe keeps its default size and splicing still works, just in more ops.)
    discard fcntl(fds[1], F_SETPIPE_SZ, (SpliceChunkSize * 2).cint)
    conn.splicePipe = fds
    conn.splicePipeOk = true
    true

  proc submitSpliceFileToPipe(conn: Connection) =
    ## SPLICE(file → pipeW): move a chunk of the file into the splice pipe.
    let toMove = min(conn.sendFileRemain, SpliceChunkSize.int64).int
    conn.sendState = sfSpliceRead
    conn.sendFileToken = conn.loop.submitOp(proc(sqe: ptr IoUringSqe) =
        sqe.prepSplice(conn.sendFileFd, conn.sendFileOff,
                       conn.splicePipe[1].int, -1, toMove, 0)
      , conn.spliceCb)

  proc submitSplicePipeToSocket(conn: Connection) =
    ## SPLICE(pipeR → socket): push the bytes currently in the pipe to the peer.
    let toMove = conn.spliceChunk - conn.spliceSent
    conn.sendState = sfSpliceSend
    conn.sendFileToken = conn.loop.submitOp(proc(sqe: ptr IoUringSqe) =
        sqe.prepSplice(conn.splicePipe[0].int, -1,
                       conn.fd.int, -1, toMove, 0)
      , conn.spliceCb)

  proc onSpliceComplete(conn: Connection, token: uint64, res: int32, flags: uint32) =
    if conn.sendFileToken != token:
      return
    if conn.retireSettled(token):
      return
    conn.sendFileToken = 0
    if conn.state == Closed:
      return
    case conn.sendState
    of sfSpliceRead:
      if res <= 0:
        # EOF (0) or error on the file leg. A file shorter than the declared
        # Content-Length still sends what it has; pumpSendFile sees remain > 0
        # and just finishes the transfer.
        conn.closeSplicePipe()
        closeFile(conn.sendFileFd)
        conn.sendFileFd = -1
        conn.sendState = sfIdle
        conn.pumpSendFile()
        return
      conn.spliceChunk = res
      conn.spliceSent = 0
      conn.sendFileOff += res.int64
      conn.sendFileRemain -= res.int64
      conn.submitSplicePipeToSocket()
    of sfSpliceSend:
      if res < 0:
        if res == -EAGAIN:
          conn.socketWritableWait()
          return
        conn.closeSplicePipe()
        conn.close()
        conn.fireClose()
        return
      if res == 0:
        # Socket can't take more right now; retry when it drains.
        conn.socketWritableWait()
        return
      conn.spliceSent += res
      if conn.spliceSent >= conn.spliceChunk:
        conn.sendState = sfIdle
        conn.pumpSendFile()
      else:
        conn.submitSplicePipeToSocket()
    else:
      discard

  proc pumpSendFile(conn: Connection) =
    if conn.sendFileFd < 0:
      # Transfer complete (or never started): the splice pipe is not needed.
      conn.closeSplicePipe()
      if conn.writeBuf.len > 0:
        conn.armWrite()
      elif conn.closePending:
        conn.closePending = false
        conn.finishClose()
        if conn.server != nil:
          conn.server.releaseConnection(conn)
        elif not conn.retiring:
          if conn.readBuf != nil:
            releaseBuf(conn.loop, conn.readBuf)
            conn.readBuf = nil
      elif conn.closeAfterFlush:
        conn.close()
        conn.fireClose()
      elif conn.shutdownAfterSend:
        conn.state = Closing
        conn.ringShutdown()
      else:
        conn.armRead()
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
      when not defined(powpowNoSplice):
        if conn.loop.supportsOp(uring.IORING_OP_SPLICE) and
           conn.ensureSplicePipe():
          # Zero-copy: SPLICE the file into a per-connection pipe, then SPLICE
          # the pipe to the socket — page cache → socket without a user-space
          # copy.
          conn.submitSpliceFileToPipe()
          return
      # READ + SEND chunk pump: read a chunk of the file into sendChunk, then
      # SEND it to the socket.
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
        , conn.sendFileReadCb)
    of sfSpliceSend:
      # Pipe→socket leg parked on -EAGAIN/0: retry once the socket drains.
      if conn.spliceSent < conn.spliceChunk:
        conn.submitSplicePipeToSocket()
      else:
        conn.sendState = sfIdle
        conn.pumpSendFile()
    of sfReading, sfSending, sfSpliceRead:
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
    if conn.writeToken == 0 and conn.writeBuf.len == 0 and conn.sendFileFd < 0 and not conn.zcPending:
      # Synchronous-write fast path: small responses fit the socket buffer, so
      # send immediately and skip the SEND op + completion round-trip entirely.
      var pos = 0
      while pos < data.len:
        let n = sockSend(conn.fd, unsafeAddr data[pos], data.len - pos)
        if n < 0:
          if sockWouldBlock():
            break
          conn.close()
          return -1
        if n == 0:
          break
        pos += n
      if pos >= data.len:
        return data.len
      # Partial write: buffer the remainder and let the SEND-op pump drain it.
      conn.writeBuf.setLen(data.len - pos)
      copyMem(addr conn.writeBuf[0], unsafeAddr data[pos], data.len - pos)
      conn.writePos = 0
      if not conn.corked:
        setTcpCork(conn.fd, true)
        conn.corked = true
      conn.armWrite()
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
    if conn.writeToken == 0 and conn.writeBuf.len == 0 and conn.sendFileFd < 0 and not conn.zcPending:
      # Synchronous-write fast path (writev): in the common case the whole
      # scatter list fits the socket buffer, so send immediately and skip the
      # SEND op + completion round-trip. Falls back to the SEND-op pump on a
      # partial write / EAGAIN.
      const MaxStackIovs = 128
      var stackIovs: array[MaxStackIovs, IOVec]
      var heapIovs: seq[IOVec]
      var iovBuf: ptr IOVec
      var iovLen: int
      template initIovec(base: ptr UncheckedArray[byte], ln: int): IOVec =
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
      if n >= totalLen:
        return totalLen
      if n < 0:
        if not sockWouldBlock():
          conn.close()
          return -1
        # EAGAIN: nothing written; coalesce everything for the SEND-op pump.
        conn.writeBuf.setLen(totalLen)
        var pos = 0
        for part in parts:
          copyMem(addr conn.writeBuf[pos], part.data, part.len)
          pos += part.len
        conn.writePos = 0
        if not conn.corked:
          setTcpCork(conn.fd, true)
          conn.corked = true
        conn.armWrite()
        return totalLen
      # Partial write: buffer only the unsent remainder.
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
      let remaining = totalLen - n
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
      if not conn.corked:
        setTcpCork(conn.fd, true)
        conn.corked = true
      conn.armWrite()
      return totalLen
    if conn.writeBuf.len > 0 or conn.writeToken != 0:
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
      conn.ringShutdown()

  proc closeAfterDrain*(conn: Connection) {.inline, gcsafe.} =
    if conn.state == Closed: return
    if conn.writeBuf.len == 0 and conn.sendFileFd < 0:
      when defined(linux):
        if conn.tlsState == TlsOff:
          conn.state = Closing
          conn.ringShutdown()
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
    if conn.retiring:
      # In-flight ops still reference the read buffer; retireFinalize releases
      # it once they settle.
      return
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

  proc onTlsWriteComplete(conn: Connection, token: uint64, res: int32, flags: uint32) =
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
      if conn.tlsPending.len > 0:
        conn.tlsOutBuf = conn.tlsPending
        conn.tlsPending.setLen(0)
        conn.armTlsWrite()
        return
      if conn.closePending:
        conn.closePending = false
        conn.finishClose()
        if conn.server != nil:
          conn.server.releaseConnection(conn)
        elif not conn.retiring:
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
      conn.armTlsWrite()

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
    if conn.fixedFd:
      sqe.flags = IOSQE_FIXED_FILE.uint8
    sqe.paddr = cast[uint64](addr conn.tlsOutBuf[start])
    sqe.len = (conn.tlsOutBuf.len - start).uint32
    conn.tlsWriteToken = conn.loop.commitOp(sqe, conn.tlsWriteCb)

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
      if conn.tlsWriteToken != 0:
        # A SEND is in flight referencing tlsOutBuf; coalesce here instead of
        # growing the in-flight seq (a reallocation would free the very memory
        # the kernel SEND is reading).
        conn.tlsPending.add(buf.toOpenArray(0, n - 1))
      else:
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

  proc initOpCallbacks(conn: Connection) =
    ## Allocate the per-connection op completion callbacks once. They persist
    ## for the connection's whole lifetime (including across pooling), so the
    ## hot path (armRead/armWrite/armTlsWrite) allocates nothing per op.
    if conn.readCb != nil:
      return
    conn.readCb = proc(token: uint64, res: int32, flags: uint32) =
      conn.onReadComplete(token, res, flags)
    conn.writeCb = proc(token: uint64, res: int32, flags: uint32) =
      conn.onWriteComplete(token, res, flags)
    conn.tlsWriteCb = proc(token: uint64, res: int32, flags: uint32) =
      conn.onTlsWriteComplete(token, res, flags)
    conn.sendFileReadCb = proc(token: uint64, res: int32, flags: uint32) =
      conn.onSendFileReadComplete(token, res, flags)
    conn.spliceCb = proc(token: uint64, res: int32, flags: uint32) =
      conn.onSpliceComplete(token, res, flags)
    conn.shutdownCb = proc(token: uint64, res: int32, flags: uint32) =
      conn.onShutdownComplete(token, res, flags)
    when defined(powpowBufferSelect):
      conn.bufferReadCb = proc(token: uint64, res: int32, flags: uint32) =
        conn.onBufferReadComplete(token, res, flags)

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
      result.fixedFd = false
      result.tlsOutBuf.setLen(0)
      result.tlsOutPos = 0
      result.tlsWriteToken = 0
      result.zcPending = false
      result.splicePipe = [-1.cint, -1.cint]
      result.splicePipeOk = false
      result.spliceChunk = 0
      result.spliceSent = 0
      result.pendingBuf.setLen(0)
      result.tlsPending.setLen(0)
    else:
      result = Connection(
        fd:        fd,
        loop:      server.loop,
        server:    server,
        state:     Connected,
        sendFileFd: -1,
        readBuf:   acquireBuf(server.loop),
        readBufLen: DefaultBufSize,
        splicePipe: [-1.cint, -1.cint],
      )
    result.initOpCallbacks()

  proc releaseConnection(server: TcpServer, conn: Connection) =
    if conn.retiring:
      # A retired connection's buffers stay alive until its in-flight ops
      # settle; retireFinalize releases them. Never re-pool it.
      return
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
    conn.fixedFd = false
    conn.zcPending = false
    conn.splicePipe = [-1.cint, -1.cint]
    conn.splicePipeOk = false
    conn.spliceChunk = 0
    conn.spliceSent = 0
    conn.pendingBuf.setLen(0)
    conn.tlsPending.setLen(0)
    if server.connPool.len < MaxConnPoolSize:
      server.connPool.add(conn)
    else:
      if conn.readBuf != nil:
        releaseBuf(conn.loop, conn.readBuf)
        conn.readBuf = nil

  # ── TcpServer ────────────────────────────────────────────────────────────────

  proc armAcceptSlot(server: TcpServer, slot: int): bool =
    ## Submit one one-shot IORING_OP_ACCEPT into `slot`. Returns false when the
    ## SQE could not be claimed (ring full) — the caller defers a retry.
    if server.acceptTokens[slot] != 0:
      return true
    let sqe = server.loop.getOpSqe()
    if sqe == nil:
      return false
    server.acceptAddrLens[slot] = sizeof(server.acceptAddrs[slot]).SockLen
    sqe.opcode = IORING_OP_ACCEPT.uint8
    sqe.fd = server.fd.int32
    if server.fixedFd:
      sqe.flags = IOSQE_FIXED_FILE.uint8
    sqe.paddr = cast[uint64](addr server.acceptAddrs[slot])
    sqe.off = cast[uint64](addr server.acceptAddrLens[slot])  # kernel 5.15: socklen_t* in addr2
    server.acceptTokens[slot] = server.loop.commitOp(sqe, server.acceptCb)
    true

  proc armAccept(server: TcpServer) =
    ## Keep accepts armed. On kernel >= 6.0 (unless disabled or rejected) a
    ## single multishot IORING_OP_ACCEPT delivers every pending connection as a
    ## completion with no re-arm; otherwise up to `AcceptBatch` one-shot ACCEPT
    ## ops stay in flight so a connection burst drains in one enter pass.
    when not defined(powpowNoMultishotAccept):
      if server.acceptMultishot:
        return
      if not server.acceptMultishotFailed and kernelAtLeast(6, 0) and
         server.loop.supportsOp(uring.IORING_OP_ACCEPT):
        let sqe = server.loop.getOpSqe()
        if sqe == nil:
          server.loop.deferCall(proc() =
            if server.fd.int >= 0:
              server.armAccept())
          return
        sqe.opcode = IORING_OP_ACCEPT.uint8
        sqe.fd = server.fd.int32
        if server.fixedFd:
          sqe.flags = IOSQE_FIXED_FILE.uint8
        # addr/addrlen must be NULL for multishot accept (the client address is
        # read via getpeername in the completion handler).
        sqe.opFlags = IORING_ACCEPT_MULTISHOT.uint32
        server.acceptTokens[0] = server.loop.commitOp(sqe, server.acceptCb)
        server.acceptMultishot = true
        return
    for slot in 0 ..< AcceptBatch:
      if server.acceptTokens[slot] != 0:
        continue
      # Never monopolize a small SQ ring: leave room for the loop's timeout and
      # wake/re-arm ops, or the next idle iteration cannot arm a timeout and
      # the blocking io_uring_enter would sleep forever on completions that
      # never come.
      if server.loop.pendingSubmit() + AcceptReserveSlots >=
         server.loop.ringEntries():
        server.loop.deferCall(proc() =
          if server.fd.int >= 0:
            server.armAccept())
        return
      if not server.armAcceptSlot(slot):
        server.loop.deferCall(proc() =
          if server.fd.int >= 0:
            server.armAccept())
        return

  proc onAcceptComplete(server: TcpServer, token: uint64, res: int32, flags: uint32) =
    var slot = -1
    for i in 0 ..< AcceptBatch:
      if server.acceptTokens[i] == token:
        slot = i
        break
    if slot < 0:
      # Stale completion from a prior lifecycle; ignore.
      return
    if server.fd.int < 0:
      return
    when not defined(powpowNoMultishotAccept):
      if server.acceptMultishot:
        # One multishot op stays armed as long as IORING_CQE_F_MORE is set; slot
        # 0 is only released when the op truly ends.
        if res < 0:
          server.acceptTokens[slot] = 0
          server.acceptMultishot = false
          if res == -EINVAL:
            # Kernel does not support multishot accept; use the one-shot batch.
            server.acceptMultishotFailed = true
          server.armAccept()
          return
        let clientFd = SocketHandle(res)
        setNonBlocking(clientFd)
        setTcpNoDelay(clientFd)
        if server.maxConnections > 0 and
           server.fdConn.len >= server.maxConnections:
          sockClose(clientFd)
        else:
          let conn = server.acquireConnection(clientFd)
          conn.fixedFd = server.loop.registerFixedFd(clientFd.int)
          var addrLen: SockLen = sizeof(conn.clientAddr).SockLen
          discard getpeername(clientFd,
                              cast[ptr Sockaddr](addr conn.clientAddr), addr addrLen)
          if server.onAccept != nil:
            server.onAccept(conn)
          if conn.state == Closed:
            server.releaseConnection(conn)
          else:
            server.fdConn[clientFd.int] = conn
            conn.armRead()
        if (flags and IORING_CQE_F_MORE.uint32) == 0:
          server.acceptTokens[slot] = 0
          server.armAccept()
        return
    server.acceptTokens[slot] = 0
    if res < 0:
      # EAGAIN/EINTR/errors: keep the slot armed.
      discard server.armAcceptSlot(slot)
      return
    let clientFd = SocketHandle(res)
    setNonBlocking(clientFd)
    setTcpNoDelay(clientFd)
    if server.maxConnections > 0 and
       server.fdConn.len >= server.maxConnections:
      sockClose(clientFd)
      discard server.armAcceptSlot(slot)
      return
    let conn = server.acquireConnection(clientFd)
    conn.fixedFd = server.loop.registerFixedFd(clientFd.int)
    conn.clientAddr = server.acceptAddrs[slot]
    if server.onAccept != nil:
      server.onAccept(conn)
    if conn.state == Closed:
      server.releaseConnection(conn)
      discard server.armAcceptSlot(slot)
      return
    server.fdConn[clientFd.int] = conn
    conn.armRead()
    discard server.armAcceptSlot(slot)

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
    server.fixedFd = server.loop.registerFixedFd(fd.int)
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
      server.fixedFd = server.loop.registerFixedFd(fd.int)
      server.armAccept()

  proc close*(server: TcpServer) {.gcsafe.} =
    for conn in server.connPool:
      if conn.readBuf != nil:
        releaseBuf(conn.loop, conn.readBuf)
        conn.readBuf = nil
    server.connPool.setLen(0)
    when iouEnabled:
      for i in 0 ..< AcceptBatch:
        if server.acceptTokens[i] != 0:
          server.loop.cancelOp(server.acceptTokens[i])
          server.acceptTokens[i] = 0
    if server.fd.int >= 0:
      server.loop.unregister(server.fd.int)
      if server.fixedFd:
        server.loop.unregisterFixedFd(server.fd.int)
        server.fixedFd = false
      sockClose(server.fd)
      server.fd = SocketHandle(-1)
    if server.unixPath.len > 0:
      when not defined(windows):
        proc c_unlink(path: cstring): cint {.importc: "unlink", header: "<unistd.h>".}
        discard c_unlink(server.unixPath.cstring)
      server.unixPath.setLen(0)

  proc injectFd*(server: TcpServer, clientFd: SocketHandle) =
    let conn = server.acquireConnection(clientFd)
    conn.fixedFd = server.loop.registerFixedFd(clientFd.int)
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
    srv.acceptCb = proc(token: uint64, res: int32, flags: uint32) =
      srv.onAcceptComplete(token, res, flags)
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
            splicePipe: [-1.cint, -1.cint],
          )
          conn.initOpCallbacks()
          let sLen = getSockLen(addr addrBuf)
          conn.connectAddr = addrBuf
          conn.fixedFd = loop.registerFixedFd(fd.int)
          conn.connectToken = loop.submitOp(proc(sqe: ptr IoUringSqe) =
              sqe.opcode = IORING_OP_CONNECT.uint8
              sqe.fd = fd.int32
              if conn.fixedFd:
                sqe.flags = IOSQE_FIXED_FILE.uint8
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
        splicePipe: [-1.cint, -1.cint],
      )
      conn.initOpCallbacks()

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

      conn.fixedFd = loop.registerFixedFd(fd.int)
      conn.connectToken = loop.submitOp(proc(sqe: ptr IoUringSqe) =
          sqe.opcode = IORING_OP_CONNECT.uint8
          sqe.fd = fd.int32
          if conn.fixedFd:
            sqe.flags = IOSQE_FIXED_FILE.uint8
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
