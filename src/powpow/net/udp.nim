## powpow/net/udp.nim — Non-blocking UDP socket.
##
## Built on top of the powpow event loop for high-performance datagram I/O.

import ../loop
import ../types
import common
import std/posix

# ── Types ────────────────────────────────────────────────────────────────────

type
  UdpMessage* {.acyclic.} = object
    ## A received UDP datagram along with its source address.
    data*:    seq[byte]
    sender*:  Sockaddr_storage
    senderLen*: SockLen

  OnUdpData* = proc(msg: UdpMessage) {.closure.}
    ## Called when a UDP datagram arrives.

  UdpSocket* {.acyclic.} = ref object
    ## A non-blocking UDP socket.
    fd*:    SocketHandle
    loop*:  Loop
    onData: OnUdpData
    readBuf:    ptr UncheckedArray[byte]
    readBufLen: int

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc close*(sock: UdpSocket) =
  ## Close the UDP socket.
  if sock.fd.int >= 0:
    sock.loop.unregister(sock.fd.int)
    discard posix.close(sock.fd.cint)
    sock.fd = SocketHandle(-1)
  if sock.readBuf != nil:
    deallocShared(sock.readBuf)
    sock.readBuf = nil

# ── I/O ──────────────────────────────────────────────────────────────────────

proc sendTo*(sock: UdpSocket, data: openArray[byte],
             address: string, port: int): int =
  ## Send a datagram to `address:port`. Returns bytes sent.
  let addrBuf = resolveAddr(address, port, SOCK_DGRAM)
  let sLen = getSockLen(addr addrBuf)
  let n = posix.sendto(sock.fd,
                        unsafeAddr data[0], data.len, 0,
                        cast[ptr Sockaddr](addr addrBuf), sLen)
  if n < 0:
    if errno == EAGAIN or errno == EWOULDBLOCK:
      return 0
    return -1
  return n

proc sendTo*(sock: UdpSocket, data: string,
             address: string, port: int): int =
  ## Convenience overload for sending strings.
  sock.sendTo(data.toOpenArrayByte(0, data.high), address, port)

proc send*(sock: UdpSocket, data: openArray[byte]): int =
  ## Send to the connected peer (requires prior `connect` or bind+connect).
  let n = posix.send(sock.fd, unsafeAddr data[0], data.len, 0)
  if n < 0:
    if errno == EAGAIN or errno == EWOULDBLOCK:
      return 0
    return -1
  return n

proc send*(sock: UdpSocket, data: string): int =
  ## Convenience overload for sending strings.
  sock.send(data.toOpenArrayByte(0, data.high))

# ── Internal read handler ────────────────────────────────────────────────────

proc handleRead(sock: UdpSocket) =
  ## Drain all pending datagrams from the socket.
  while true:
    var sender: Sockaddr_storage
    var senderLen: SockLen = sizeof(sender).SockLen
    let n = posix.recvfrom(sock.fd, addr sock.readBuf[0],
                           sock.readBufLen, 0,
                           cast[ptr Sockaddr](addr sender), addr senderLen)
    if n > 0:
      var msg = UdpMessage(
        data:       newSeq[byte](n),
        sender:     sender,
        senderLen:  senderLen,
      )
      copyMem(addr msg.data[0], addr sock.readBuf[0], n)
      sock.onData(msg)
    elif n == 0:
      return  # Empty datagram — ignore
    else:
      if errno == EAGAIN or errno == EWOULDBLOCK:
        return  # No more datagrams
      return  # Error — skip

# ── Server (bind + listen) ───────────────────────────────────────────────────

proc bindUdp*(loop: Loop, address: string, port: int,
              onData: OnUdpData): UdpSocket =
  ## Create a UDP socket bound to `address:port` and register it for reads.
  let addrBuf = resolveAddr(address, port, SOCK_DGRAM)
  let fd = socket(cast[ptr Sockaddr](addr addrBuf).sa_family.cint,
                  SOCK_DGRAM.cint, 0)
  if fd.cint < 0:
    raise newException(NetError, "socket() failed")

  setNonBlocking(SocketHandle(fd))
  setReuseAddr(SocketHandle(fd))

  let sLen = getSockLen(addr addrBuf)
  if bindSocket(fd, cast[ptr Sockaddr](addr addrBuf), sLen) < 0:
    discard posix.close(fd)
    raise newException(NetError, "bind() failed")

  let sock = UdpSocket(
    fd:         SocketHandle(fd),
    loop:       loop,
    onData:     onData,
    readBuf:    cast[ptr UncheckedArray[byte]](allocShared(DefaultBufSize)),
    readBufLen: DefaultBufSize,
  )

  loop.register(fd.int, {Read}) do (rfd: int, ev: set[EventType]):
    if Read in ev:
      sock.handleRead()

  return sock

# ── Client (connect to a specific peer) ──────────────────────────────────────

proc connectUdp*(loop: Loop, address: string, port: int,
                 onData: OnUdpData = nil): UdpSocket =
  ## Create a UDP socket connected to `address:port`.
  ## `onData` fires when datagrams arrive from the connected peer.
  let addrBuf = resolveAddr(address, port, SOCK_DGRAM)
  let fd = socket(cast[ptr Sockaddr](addr addrBuf).sa_family.cint,
                  SOCK_DGRAM.cint, 0)
  if fd.cint < 0:
    raise newException(NetError, "socket() failed")

  setNonBlocking(SocketHandle(fd))

  let sLen = getSockLen(addr addrBuf)
  let ret = posix.connect(fd, cast[ptr Sockaddr](addr addrBuf), sLen)
  if ret < 0 and errno != EINPROGRESS:
    discard posix.close(fd)
    raise newException(NetError, "connect() failed")

  let sock = UdpSocket(
    fd:         SocketHandle(fd),
    loop:       loop,
    onData:     onData,
    readBuf:    cast[ptr UncheckedArray[byte]](allocShared(DefaultBufSize)),
    readBufLen: DefaultBufSize,
  )

  if onData != nil:
    loop.register(fd.int, {Read}) do (rfd: int, ev: set[EventType]):
      if Read in ev:
        sock.handleRead()

  return sock
