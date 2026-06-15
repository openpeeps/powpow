## powpow/net/tcp.nim — Non-blocking TCP server and client connections.
##
## Built on top of the powpow event loop for zero-threading, high-throughput
## TCP networking.

import ../loop
import ../types
import common
import std/posix

# ── Types ────────────────────────────────────────────────────────────────────

type
  ConnState* = enum
    ## Internal connection state.
    Connecting, Connected, Closing, Closed

  Connection* {.acyclic.} = ref object
    ## A non-blocking TCP connection.
    fd*:        SocketHandle
    loop*:      Loop
    state*:     ConnState
    readBuf:    ptr UncheckedArray[byte]
    readBufLen: int

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

# ── Connection ───────────────────────────────────────────────────────────────

proc close*(conn: Connection) =
  ## Close a TCP connection.
  if conn.state == Closed: return
  conn.state = Closed
  conn.loop.unregister(conn.fd.int)
  discard posix.close(conn.fd.cint)
  if conn.readBuf != nil:
    deallocShared(conn.readBuf)
    conn.readBuf = nil

proc send*(conn: Connection, data: openArray[byte]): int =
  ## Send data on the connection. Returns the number of bytes written.
  ## May return less than `data.len` if the kernel buffer is full.
  if conn.state != Connected: return 0
  let n = posix.send(conn.fd, unsafeAddr data[0], data.len, 0)
  if n < 0:
    if errno == EAGAIN or errno == EWOULDBLOCK:
      return 0
    conn.close()
    return -1
  return n

proc send*(conn: Connection, data: string): int =
  ## Convenience overload for sending strings.
  conn.send(data.toOpenArrayByte(0, data.high))

proc shutdown*(conn: Connection) =
  ## Gracefully shut down the write side of the connection.
  if conn.state == Connected:
    conn.state = Closing
    discard posix.shutdown(conn.fd, SHUT_WR)

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
    let clientFd = posix.accept(server.fd,
                                 cast[ptr Sockaddr](addr clientAddr),
                                 addr addrLen)
    if clientFd.int < 0:
      if errno == EAGAIN or errno == EWOULDBLOCK:
        return  # No more pending connections
      # EMFILE / ENFILE / ENOMEM etc. — re-arm the listen fd and try
      # again on the next tick so we don't busy-spin while the fd table
      # is exhausted (this is the post-benchmark 100% CPU case).
      server.loop.modify(server.fd.int, {Read})
      return

    # accept() doesn't have SOCK_NONBLOCK flag, set it manually
    setNonBlocking(clientFd)

    # Build the Connection object
    let conn = Connection(
      fd:        SocketHandle(clientFd),
      loop:      server.loop,
      state:     Connected,
      readBuf:   cast[ptr UncheckedArray[byte]](allocShared(DefaultBufSize)),
      readBufLen: DefaultBufSize,
    )

    # Notify user
    if server.onAccept != nil:
      server.onAccept(conn)
    if conn.state == Closed:
      continue  # onAccept may have closed it

    # Register for read events — edge-triggered so idle keep-alive
    # sockets don't re-fire Read on every loop tick.
    conn.loop.register(clientFd.int, {Read}, edgeTriggered = true, callback =
      proc(fd: int, ev: set[EventType]) =
        if Error in ev or Hup in ev:
          conn.close()
          if server.onClose != nil: server.onClose(conn)
          return
        if Read in ev:
          # Edge-triggered: drain until EAGAIN.
          conn.handleClientRead(server.onData, server.onClose)
    )

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
  ## Close the server socket.
  if server.fd.int >= 0:
    server.loop.unregister(server.fd.int)
    discard posix.close(server.fd.cint)
    server.fd = SocketHandle(-1)

proc injectFd*(server: TcpServer, clientFd: SocketHandle) =
  ## Take a pre-accepted client fd and wire it into this server's event loop.
  ## Used by multi-threaded acceptors that accept on one thread and
  ## distribute connections to worker threads.
  setNonBlocking(clientFd)

  let conn = Connection(
    fd:        clientFd,
    loop:      server.loop,
    state:     Connected,
    readBuf:   cast[ptr UncheckedArray[byte]](allocShared(DefaultBufSize)),
    readBufLen: DefaultBufSize,
  )

  if server.onAccept != nil:
    server.onAccept(conn)
  if conn.state == Closed:
    return

  conn.loop.register(clientFd.int, {Read}, edgeTriggered = true, callback =
    proc(fd: int, ev: set[EventType]) =
      if Error in ev or Hup in ev:
        conn.close()
        if server.onClose != nil: server.onClose(conn)
        return
      if Read in ev:
        conn.handleClientRead(server.onData, server.onClose)
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
    readBuf:   cast[ptr UncheckedArray[byte]](allocShared(DefaultBufSize)),
    readBufLen: DefaultBufSize,
  )

  let sLen = getSockLen(addr addrBuf)
  let ret = posix.connect(fd, cast[ptr Sockaddr](addr addrBuf), sLen)
  if ret < 0 and errno != EINPROGRESS:
    discard posix.close(fd)
    deallocShared(conn.readBuf)
    raise newException(NetError, "connect() failed")

  if ret == 0:
    # Connected immediately
    conn.state = Connected
    onConnect(conn)
    if conn.state == Closed: return
    conn.loop.register(fd.int, {Read}) do (rfd: int, ev: set[EventType]):
      if Error in ev or Hup in ev:
        conn.close()
        if onClose != nil: onClose(conn)
        return
      if Read in ev:
        conn.handleClientRead(onData, onClose)
  else:
    # Connection in progress — wait for writability (connect completion)
    conn.loop.register(fd.int, {Write}) do (wfd: int, ev: set[EventType]):
      conn.loop.unregister(wfd)
      # Check if connect succeeded
      var err: cint = 0
      var errLen: SockLen = sizeof(err).SockLen
      discard getsockopt(fd, SOL_SOCKET, SO_ERROR, addr err, addr errLen)
      if err != 0:
        conn.state = Closed
        discard posix.close(fd)
        deallocShared(conn.readBuf)
        return

      conn.state = Connected
      setTcpNoDelay(SocketHandle(wfd))
      onConnect(conn)
      if conn.state == Closed: return
      conn.loop.register(wfd, {Read}) do (rfd: int, ev: set[EventType]):
        if Error in ev or Hup in ev:
          conn.close()
          if onClose != nil: onClose(conn)
          return
        if Read in ev:
          conn.handleClientRead(onData, onClose)
