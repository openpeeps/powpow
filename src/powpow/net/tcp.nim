# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/net/tcp.nim — Non-blocking TCP server and client connections.
##
## Built on top of the powpow event loop for zero-threading, high-throughput
## TCP networking. Platform-agnostic: IOCP (Windows) or epoll/kqueue (Unix).

import ../loop
import ../types
import common
when not defined(windows):
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
  var lin: TLinger
  when defined(windows):
    lin.l_onoff = 1.cushort
    lin.l_linger = 0.cushort
  else:
    lin.l_onoff = 1.cint
    lin.l_linger = 0.cint
  discard setsockopt(fd, SOL_SOCKET, SO_LINGER, addr lin, sizeof(lin).SockLen)

# ── Types ────────────────────────────────────────────────────────────────────

type
  ConnState* = enum
    Connecting, Connected, Closing, Closed

  Connection* {.acyclic.} = ref object
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
  OnData*    = proc(conn: Connection, data: openArray[byte]) {.closure.}
  OnClose*   = proc(conn: Connection) {.closure.}

  TcpServer* {.acyclic.} = ref object
    fd*:       SocketHandle
    loop*:     Loop
    onAccept:  OnAccept
    onData:    OnData
    onClose*:  OnClose
    connPool:  seq[Connection]

proc shutWrVal(): cint {.inline.} =
  when defined(windows): 1 else: SHUT_WR

# ── Connection ───────────────────────────────────────────────────────────────

proc close*(conn: Connection) =
  if conn.state == Closed: return
  conn.state = Closed
  if conn.corked:
    setTcpCork(conn.fd, false)
    conn.corked = false
  setLinger0(conn.fd)
  conn.loop.unregister(conn.fd.int)
  sockClose(conn.fd)
  conn.writeBuf.setLen(0)
  conn.writePos = 0

proc flushWriteBuffer(conn: Connection): bool =
  while conn.writePos < conn.writeBuf.len:
    let remaining = conn.writeBuf.len - conn.writePos
    let n = sockSend(conn.fd,
                     unsafeAddr conn.writeBuf[conn.writePos], remaining)
    if n < 0:
      if sockWouldBlock():
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

proc send*(conn: Connection, data: openArray[byte]): int =
  if conn.state != Connected: return 0

  if conn.writeBuf.len > 0:
    let oldLen = conn.writeBuf.len
    conn.writeBuf.setLen(oldLen + data.len)
    copyMem(addr conn.writeBuf[oldLen], unsafeAddr data[0], data.len)
    return data.len

  let n = sockSend(conn.fd, unsafeAddr data[0], data.len)
  if n < 0:
    if sockWouldBlock():
      conn.writeBuf = newSeq[byte](data.len)
      copyMem(addr conn.writeBuf[0], unsafeAddr data[0], data.len)
      conn.writePos = 0
      if not conn.corked:
        setTcpCork(conn.fd, true)
        conn.corked = true
      conn.loop.modify(conn.fd.int, {Read, Write})
      return data.len
    conn.close()
    return -1

  if n < data.len:
    let remaining = data.len - n
    conn.writeBuf = newSeq[byte](remaining)
    copyMem(addr conn.writeBuf[0], unsafeAddr data[n], remaining)
    conn.writePos = 0
    if not conn.corked:
      setTcpCork(conn.fd, true)
      conn.corked = true
    conn.loop.modify(conn.fd.int, {Read, Write})

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

  if conn.writeBuf.len > 0:
    for part in parts:
      let oldLen = conn.writeBuf.len
      conn.writeBuf.setLen(oldLen + part.len)
      copyMem(addr conn.writeBuf[oldLen], part.data, part.len)
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
      return totalLen
    conn.close()
    return -1

  if n < totalLen:
    var remaining = totalLen - n
    conn.writeBuf = newSeq[byte](remaining)
    var pos = 0
    var skipped = 0
    for part in parts:
      if skipped + part.len <= n:
        skipped += part.len
      else:
        let offset = n - skipped
        let toCopy = part.len - offset
        copyMem(addr conn.writeBuf[pos],
                cast[ptr UncheckedArray[byte]](
                  cast[uint](part.data) + offset.uint), toCopy)
        pos += toCopy
        skipped = n
    conn.writePos = 0
    if not conn.corked:
      setTcpCork(conn.fd, true)
      conn.corked = true
    conn.loop.modify(conn.fd.int, {Read, Write})

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

proc closeAfterDrain*(conn: Connection) =
  if conn.state == Closed: return
  if conn.writeBuf.len == 0:
    conn.close()
  else:
    conn.closeAfterFlush = true

proc closeAndRelease*(conn: Connection) =
  conn.close()
  if conn.readBuf != nil:
    releaseBuf(conn.loop, conn.readBuf)
    conn.readBuf = nil

proc acquireConnection(server: TcpServer, fd: SocketHandle): Connection =
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
  while conn.state == Connected:
    when defined(windows):
      # On Windows, data is read asynchronously by the IOCP backend.
      # getReadData returns buffered data from a completed IOCP read.
      let n = conn.loop.platform.getReadData(
        conn.fd.int, addr conn.readBuf[0], conn.readBufLen)
    else:
      let n = sockRecv(conn.fd, addr conn.readBuf[0], conn.readBufLen)
    if n > 0:
      onData(conn, conn.readBuf.toOpenArray(0, n - 1))
      if conn.state != Connected:
        if onClose != nil: onClose(conn)
        return
    elif n == 0:
      conn.close()
      if onClose != nil: onClose(conn)
      return
    else:
      when defined(windows):
        return
      else:
        if sockInterrupted():
          continue
        return

proc acceptClients(server: TcpServer) =
  while true:
    var clientAddr: Sockaddr_storage
    var addrLen: SockLen = sizeof(clientAddr).SockLen
    let clientFd = accept(server.fd,
                          cast[ptr Sockaddr](addr clientAddr),
                          addr addrLen)
    if clientFd.int >= 0:
      setNonBlocking(SocketHandle(clientFd))

    if clientFd.int < 0:
      if sockWouldBlock():
        return
      server.loop.modify(server.fd.int, {Read})
      return

    setTcpNoDelay(clientFd)

    let conn = acquireConnection(server, clientFd)

    if server.onAccept != nil:
      server.onAccept(conn)
    if conn.state == Closed:
      continue

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

proc injectFd*(server: TcpServer, clientFd: SocketHandle) =
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
  let addrBuf = resolveAddr(address, port, SOCK_STREAM)
  let fd = socket(cast[ptr Sockaddr](addr addrBuf).sa_family.cint,
                  SOCK_STREAM, 0)
  if fd.cint < 0:
    raise newException(NetError, "socket() failed")

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
    raise newException(NetError, "connect() failed")

  if ret == 0:
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
    conn.loop.register(fd.int, {Write}) do (wfd: int, ev: set[EventType]):
      conn.loop.unregister(wfd)
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
