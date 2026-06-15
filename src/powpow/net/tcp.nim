## powpow/net/tcp.nim — Non-blocking TCP server and client connections.
##
## Built on top of the powpow event loop for zero-threading, high-throughput
## TCP networking.

import ../loop
import ../types
import common
import std/posix

const
  MaxBufPoolSize = 1024
  MaxConnPoolSize = 1024

proc acquireBuf(loop: Loop): ptr UncheckedArray[byte] =
  if loop.bufPool.len > 0:
    loop.bufPool.pop()
  else:
    cast[ptr UncheckedArray[byte]](allocShared(DefaultBufSize))

proc releaseBuf(loop: Loop, buf: ptr UncheckedArray[byte]) =
  if loop.bufPool.len < MaxBufPoolSize:
    loop.bufPool.add(buf)
  else:
    deallocShared(buf)

proc setLinger0(fd: SocketHandle) =
  # Enable SO_LINGER with l_linger=0 so close() sends RST instead of FIN,
  # eliminating TIME_WAIT on the server socket.
  var lin: TLinger
  lin.l_onoff = 1
  lin.l_linger = 0
  discard setsockopt(fd, SOL_SOCKET, SO_LINGER, addr lin, sizeof(lin).SockLen)

# ── Types ────────────────────────────────────────────────────────────────────

type
  ConnState* = enum
    ## Internal connection state.
    Connecting, Connected, Closing, Closed

  Connection* {.acyclic.} = ref object
    ## A non-blocking TCP connection.
    fd*:              SocketHandle
    loop*:            Loop
    state*:           ConnState
    readBuf:          ptr UncheckedArray[byte]
    readBufLen:       int
    writeBuf:         seq[byte]
    writePos:         int
    corked:           bool
    closeAfterFlush: bool

  OnAccept*  = proc(conn: Connection) {.closure.}
    ## Called when a new client connects.

  OnData*    = proc(conn: Connection, data: openArray[byte]) {.closure.}
    ## Called when data arrives on a connection.

  OnClose*   = proc(conn: Connection) {.closure.}
    ## Called when a connection is closed.

  TcpServer* {.acyclic.} = ref object
    ## A non-blocking TCP listening server.
    fd*:       SocketHandle
    loop*:     Loop
    onAccept:  OnAccept
    onData:    OnData
    onClose*:   OnClose
    connPool:  seq[Connection]

# ── Connection ───────────────────────────────────────────────────────────────

proc close*(conn: Connection) =
  ## Close a TCP connection.
  if conn.state == Closed: return
  conn.state = Closed
  if conn.corked:
    setTcpCork(conn.fd, false)
    conn.corked = false
  setLinger0(conn.fd)
  conn.loop.unregister(conn.fd.int)
  discard posix.close(conn.fd.cint)
  conn.writeBuf.setLen(0)
  conn.writePos = 0

proc flushWriteBuffer(conn: Connection): bool =
  ## Flush buffered data. Returns true if buffer is now empty.
  while conn.writePos < conn.writeBuf.len:
    let remaining = conn.writeBuf.len - conn.writePos
    let n = posix.send(conn.fd,
                       unsafeAddr conn.writeBuf[conn.writePos],
                       remaining, 0)
    if n < 0:
      if errno == EAGAIN or errno == EWOULDBLOCK:
        return false  # Still have data to send
      conn.close()
      return true  # Error - connection closed

    conn.writePos += n

  # Buffer fully flushed - clear it
  conn.writeBuf.setLen(0)
  conn.writePos = 0
  if conn.corked:
    setTcpCork(conn.fd, false)
    conn.corked = false
  return true

proc send*(conn: Connection, data: openArray[byte]): int =
  ## Send data on the connection. Returns the number of bytes written.
  ## Buffers data if the kernel buffer is full (EAGAIN).
  if conn.state != Connected: return 0

  # If we already have buffered data, append to buffer
  if conn.writeBuf.len > 0:
    let oldLen = conn.writeBuf.len
    conn.writeBuf.setLen(oldLen + data.len)
    copyMem(addr conn.writeBuf[oldLen], unsafeAddr data[0], data.len)
    return data.len  # All data buffered

  # Try to send directly first
  let n = posix.send(conn.fd, unsafeAddr data[0], data.len, 0)
  if n < 0:
    if errno == EAGAIN or errno == EWOULDBLOCK:
      # Buffer the unsent data
      conn.writeBuf = newSeq[byte](data.len)
      copyMem(addr conn.writeBuf[0], unsafeAddr data[0], data.len)
      conn.writePos = 0
      if not conn.corked:
        setTcpCork(conn.fd, true)
        conn.corked = true
      # Register for write events
      conn.loop.modify(conn.fd.int, {Read, Write})
      return data.len  # All data buffered
    conn.close()
    return -1

  if n < data.len:
    # Partial send - buffer the rest
    let remaining = data.len - n
    conn.writeBuf = newSeq[byte](remaining)
    copyMem(addr conn.writeBuf[0], unsafeAddr data[n], remaining)
    conn.writePos = 0
    if not conn.corked:
      setTcpCork(conn.fd, true)
      conn.corked = true
    # Register for write events
    conn.loop.modify(conn.fd.int, {Read, Write})

  return data.len  # All data either sent or buffered

proc send*(conn: Connection, data: string): int =
  ## Convenience overload for sending strings.
  conn.send(data.toOpenArrayByte(0, data.high))

proc sendv*(conn: Connection, parts: openArray[tuple[data: ptr UncheckedArray[byte], len: int]]): int =
  ## Send multiple buffers using writev (scatter-gather IO).
  ## Returns total bytes written. Buffers data if kernel buffer is full (EAGAIN).
  if conn.state != Connected: return 0

  # Calculate total length
  var totalLen = 0
  for part in parts:
    totalLen += part.len

  if totalLen == 0: return 0

  # If we already have buffered data, append to buffer
  if conn.writeBuf.len > 0:
    for part in parts:
      let oldLen = conn.writeBuf.len
      conn.writeBuf.setLen(oldLen + part.len)
      copyMem(addr conn.writeBuf[oldLen], part.data, part.len)
    return totalLen  # All data buffered

  # Build iovec array (stack-allocated for common case, heap fallback for large)
  const MaxStackIovs = 128
  var stackIovs: array[MaxStackIovs, IOVec]
  var heapIovs: seq[IOVec]
  var iovBuf: ptr IOVec
  var iovLen: int

  if parts.len <= MaxStackIovs:
    iovBuf = addr stackIovs[0]
    iovLen = parts.len
    for i in 0 ..< parts.len:
      stackIovs[i] = IOVec(iov_base: parts[i].data, iov_len: parts[i].len.csize_t)
  else:
    heapIovs = newSeq[IOVec](parts.len)
    iovBuf = addr heapIovs[0]
    iovLen = parts.len
    for i in 0 ..< parts.len:
      heapIovs[i] = IOVec(iov_base: parts[i].data, iov_len: parts[i].len.csize_t)

  # Try writev first
  let n = posix.writev(conn.fd.cint, iovBuf, iovLen.cint)
  if n < 0:
    if errno == EAGAIN or errno == EWOULDBLOCK:
      # Buffer all data
      conn.writeBuf = newSeq[byte](totalLen)
      var pos = 0
      for part in parts:
        copyMem(addr conn.writeBuf[pos], part.data, part.len)
        pos += part.len
      conn.writePos = 0
      if not conn.corked:
        setTcpCork(conn.fd, true)
        conn.corked = true
      conn.loop.modify(conn.fd.int, {Read, Write})
      return totalLen  # All data buffered
    conn.close()
    return -1

  if n < totalLen:
    # Partial write - buffer remaining
    var remaining = totalLen - n
    conn.writeBuf = newSeq[byte](remaining)
    var pos = 0
    var skipped = 0
    for part in parts:
      if skipped + part.len <= n:
        # This part was fully sent
        skipped += part.len
      else:
        # This part was partially sent or not sent
        let offset = n - skipped
        let toCopy = part.len - offset
        copyMem(addr conn.writeBuf[pos], cast[ptr UncheckedArray[byte]](cast[uint](part.data) + offset.uint), toCopy)
        pos += toCopy
        skipped = n  # Mark all as skipped for remaining parts
    conn.writePos = 0
    if not conn.corked:
      setTcpCork(conn.fd, true)
      conn.corked = true
    conn.loop.modify(conn.fd.int, {Read, Write})

  return totalLen  # All data either sent or buffered

proc shutdown*(conn: Connection) =
  ## Gracefully shut down the write side of the connection.
  ## Flushes any buffered data before shutting down.
  if conn.state != Connected: return
  if conn.writeBuf.len > 0:
    discard conn.flushWriteBuffer()
  elif conn.corked:
    setTcpCork(conn.fd, false)
    conn.corked = false
  if conn.state != Connected: return
  conn.state = Closing
  discard posix.shutdown(conn.fd, SHUT_WR)

proc closeAfterDrain*(conn: Connection) =
  ## Close the connection after the write buffer drains.
  ## If the buffer is empty, closes immediately — saving a shutdown()
  ## syscall compared to the graceful shutdown path.
  ## If the buffer has pending data, sets closeAfterFlush so the
  ## Write event handler closes after draining.
  if conn.state == Closed: return
  if conn.writeBuf.len == 0:
    conn.close()
  else:
    conn.closeAfterFlush = true

proc closeAndRelease*(conn: Connection) =
  ## Close a connection and release all resources for good.
  ## Unlike plain close(), this frees the readBuf back to the pool.
  ## Used for client-side connections (connect) that don't have a TcpServer pool.
  conn.close()
  if conn.readBuf != nil:
    releaseBuf(conn.loop, conn.readBuf)
    conn.readBuf = nil

proc acquireConnection(server: TcpServer, fd: SocketHandle): Connection =
  ## Obtain a Connection from the pool or create a new one.
  if server.connPool.len > 0:
    result = server.connPool.pop()
    result.fd = fd
    result.loop = server.loop
    result.state = Connected
  else:
    result = Connection(
      fd:        fd,
      loop:      server.loop,
      state:     Connected,
      readBuf:   acquireBuf(server.loop),
      readBufLen: DefaultBufSize,
    )

proc releaseConnection(server: TcpServer, conn: Connection) =
  ## Reset a Connection and return it to the pool for reuse.
  conn.state = Closed
  conn.fd = SocketHandle(-1)
  conn.corked = false
  conn.closeAfterFlush = false
  conn.writeBuf.setLen(0)
  conn.writePos = 0
  if server.connPool.len < MaxConnPoolSize:
    server.connPool.add(conn)
  else:
    if conn.readBuf != nil:
      releaseBuf(conn.loop, conn.readBuf)
      conn.readBuf = nil

# ── TcpServer ────────────────────────────────────────────────────────────────

proc handleClientRead(conn: Connection, onData: OnData, onClose: OnClose) =
  ## Internal: read handler for accepted client connections.
  while conn.state == Connected:
    let n = posix.recv(conn.fd, addr conn.readBuf[0],
                       conn.readBufLen, 0)
    if n > 0:
      onData(conn, conn.readBuf.toOpenArray(0, n - 1))
      # onData may have closed the connection — notify and bail
      if conn.state != Connected:
        if onClose != nil: onClose(conn)
        return
    elif n == 0:
      # Peer closed connection
      conn.close()
      if onClose != nil: onClose(conn)
      return
    else:
      if errno == EAGAIN or errno == EWOULDBLOCK:
        return  # No more data right now
      if errno == EINTR:
        continue  # interrupted by signal — retry
      # Real error
      conn.close()
      if onClose != nil: onClose(conn)
      return

proc acceptClients(server: TcpServer) =
  ## Internal: accept all pending connections (edge-triggered safe loop).
  while true:
    var clientAddr: Sockaddr_storage
    var addrLen: SockLen = sizeof(clientAddr).SockLen
    when defined(linux):
      const SockFlags = O_NONBLOCK or O_CLOEXEC
      let clientFd = posix.accept4(server.fd,
                                   cast[ptr Sockaddr](addr clientAddr),
                                   addr addrLen, SockFlags)
    else:
      let clientFd = posix.accept(server.fd,
                                   cast[ptr Sockaddr](addr clientAddr),
                                   addr addrLen)
      if clientFd.int >= 0:
        setNonBlocking(clientFd)

    if clientFd.int < 0:
      if errno == EAGAIN or errno == EWOULDBLOCK:
        return  # No more pending connections
      # EMFILE / ENFILE / ENOMEM etc. — re-arm the listen fd and try
      # again on the next tick so we don't busy-spin while the fd table
      # is exhausted (this is the post-benchmark 100% CPU case).
      server.loop.modify(server.fd.int, {Read})
      return

    setTcpNoDelay(SocketHandle(clientFd))

    # Build the Connection object (reuse from pool if available)
    let conn = acquireConnection(server, SocketHandle(clientFd))

    # Notify user
    if server.onAccept != nil:
      server.onAccept(conn)
    if conn.state == Closed:
      continue  # onAccept may have closed it

    # Register for read events — edge-triggered so idle keep-alive
    # sockets don't re-fire Read on every loop tick.
    conn.loop.register(clientFd.int, {Read}, edgeTriggered = true, callback =
      proc(fd: int, ev: set[EventType]) =
        if Error in ev:
          conn.close()
          if server.onClose != nil: server.onClose(conn)
          server.releaseConnection(conn)
          return
        if Write in ev:
          if conn.flushWriteBuffer():
            if conn.closeAfterFlush:
              conn.close()
              if server.onClose != nil: server.onClose(conn)
              server.releaseConnection(conn)
              return
            if conn.state == Connected:
              conn.loop.modify(fd, {Read})
        if Read in ev or Hup in ev:
          conn.handleClientRead(server.onData, server.onClose)
        if Hup in ev and conn.state == Connected:
          conn.close()
          if server.onClose != nil: server.onClose(conn)
        if conn.state == Closed:
          server.releaseConnection(conn)
    )
    # Immediately check for data that may have arrived before the
    # edge-triggered EPOLL_CTL_ADD — on some kernels, that data is
    # never reported as an event.
    conn.handleClientRead(server.onData, server.onClose)
    if conn.state == Closed:
      server.releaseConnection(conn)
      continue

proc listen*(server: TcpServer, address: string, port: int) =
  ## Bind and start listening for connections.
  let addrBuf = resolveAddr(address, port, SOCK_STREAM)
  let fd = socket(cast[ptr Sockaddr](addr addrBuf).sa_family.cint,
                  SOCK_STREAM.cint, 0)
  if fd.cint < 0:
    raise newException(NetError, "socket() failed")

  setNonBlocking(SocketHandle(fd))
  setReuseAddr(SocketHandle(fd))
  setReusePort(SocketHandle(fd))

  let sLen = getSockLen(addr addrBuf)
  if bindSocket(fd, cast[ptr Sockaddr](addr addrBuf), sLen) < 0:
    discard posix.close(fd)
    raise newException(NetError, "bind() failed")

  if posix.listen(fd, SOMAXCONN) < 0:
    discard posix.close(fd)
    raise newException(NetError, "listen() failed")

  server.fd = SocketHandle(fd)

  # Register the listen fd for read events (incoming connections)
  server.loop.register(fd.int, {Read}) do (listenFd: int, ev: set[EventType]):
    server.acceptClients()

proc close*(server: TcpServer) =
  ## Close the server socket and release pooled connections.
  for conn in server.connPool:
    if conn.readBuf != nil:
      releaseBuf(conn.loop, conn.readBuf)
      conn.readBuf = nil
  server.connPool.setLen(0)
  if server.fd.int >= 0:
    server.loop.unregister(server.fd.int)
    discard posix.close(server.fd.cint)
    server.fd = SocketHandle(-1)

proc injectFd*(server: TcpServer, clientFd: SocketHandle) =
  ## Take a pre-accepted client fd and wire it into this server's event loop.
  ## Used by multi-threaded acceptors that accept on one thread and
  ## distribute connections to worker threads.
  ## The fd must already be non-blocking with TCP_NODELAY set.

  let conn = acquireConnection(server, clientFd)

  if server.onAccept != nil:
    server.onAccept(conn)
  if conn.state == Closed:
    return

  conn.loop.register(clientFd.int, {Read}, edgeTriggered = true, callback =
    proc(fd: int, ev: set[EventType]) =
      if Error in ev:
        conn.close()
        if server.onClose != nil: server.onClose(conn)
        server.releaseConnection(conn)
        return
      if Write in ev:
        if conn.flushWriteBuffer():
          if conn.closeAfterFlush:
            conn.close()
            if server.onClose != nil: server.onClose(conn)
            server.releaseConnection(conn)
            return
          if conn.state == Connected:
            conn.loop.modify(fd, {Read})
      if Read in ev or Hup in ev:
        conn.handleClientRead(server.onData, server.onClose)
      if Hup in ev and conn.state == Connected:
        conn.close()
        if server.onClose != nil: server.onClose(conn)
      if conn.state == Closed:
        server.releaseConnection(conn)
  )

proc newTcpServer*(loop: Loop,
                   onData: OnData,
                   onAccept: OnAccept = nil,
                   onClose: OnClose = nil): TcpServer =
  ## Create a new TCP server. Call `server.listen(address, port)` to start.
  TcpServer(
    fd:       SocketHandle(-1),
    loop:     loop,
    onAccept: onAccept,
    onData:   onData,
    onClose:  onClose,
    connPool: @[],
  )

# ── Client connect ───────────────────────────────────────────────────────────

proc connect*(loop: Loop, address: string, port: int,
              onConnect: proc(conn: Connection) {.closure.},
              onData: OnData,
              onClose: OnClose = nil) =
  ## Connect to a remote TCP server. `onConnect` fires when the connection
  ## is established. `onData` fires when data arrives.
  let addrBuf = resolveAddr(address, port, SOCK_STREAM)
  let fd = socket(cast[ptr Sockaddr](addr addrBuf).sa_family.cint,
                  SOCK_STREAM.cint, 0)
  if fd.cint < 0:
    raise newException(NetError, "socket() failed")

  setNonBlocking(SocketHandle(fd))
  setTcpNoDelay(SocketHandle(fd))

  let conn = Connection(
    fd:        SocketHandle(fd),
    loop:      loop,
    state:     Connecting,
    readBuf:   acquireBuf(loop),
    readBufLen: DefaultBufSize,
  )

  let sLen = getSockLen(addr addrBuf)
  let ret = posix.connect(fd, cast[ptr Sockaddr](addr addrBuf), sLen)
  if ret < 0 and errno != EINPROGRESS:
    conn.closeAndRelease()
    raise newException(NetError, "connect() failed")

  if ret == 0:
    # Connected immediately
    conn.state = Connected
    conn.loop.register(fd.int, {Read}) do (rfd: int, ev: set[EventType]):
      if Error in ev:
        conn.closeAndRelease()
        if onClose != nil: onClose(conn)
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
    # Connection in progress — wait for writability (connect completion)
    conn.loop.register(fd.int, {Write}) do (wfd: int, ev: set[EventType]):
      conn.loop.unregister(wfd)
      # Check if connect succeeded
      var err: cint = 0
      var errLen: SockLen = sizeof(err).SockLen
      discard getsockopt(fd, SOL_SOCKET, SO_ERROR, addr err, addr errLen)
      if err != 0:
        conn.closeAndRelease()
        return

      conn.state = Connected
      setTcpNoDelay(SocketHandle(wfd))
      conn.loop.register(wfd, {Read}) do (rfd: int, ev: set[EventType]):
        if Error in ev:
          conn.closeAndRelease()
          if onClose != nil: onClose(conn)
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
