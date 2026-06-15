# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## This module provides UDP socket support for powpow, including both server (bind) and client (connect) modes.
## It defines the `UdpSocket` type and related procedures for sending and receiving UDP messages in an event
## loop.

import ../loop
import ../types
import common
when not defined(windows):
  import std/posix

# ── Types ────────────────────────────────────────────────────────────────────

type
  UdpMessage* {.acyclic.} = object
    data*:    seq[byte]
    sender*:  Sockaddr_storage
    senderLen*: SockLen

  OnUdpData* = proc(msg: UdpMessage) {.closure.}

  UdpSocket* {.acyclic.} = ref object
    fd*:    SocketHandle
    loop*:  Loop
    onData: OnUdpData
    readBuf:    ptr UncheckedArray[byte]
    readBufLen: int

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc close*(sock: UdpSocket) =
  if sock.fd.int >= 0:
    sock.loop.unregister(sock.fd.int)
    sockClose(sock.fd)
    sock.fd = SocketHandle(-1)
  if sock.readBuf != nil:
    deallocShared(sock.readBuf)
    sock.readBuf = nil

# ── I/O ──────────────────────────────────────────────────────────────────────

proc sendTo*(sock: UdpSocket, data: openArray[byte],
             address: string, port: int): int =
  let addrBuf = resolveAddr(address, port, SOCK_DGRAM)
  let sLen = getSockLen(addr addrBuf)
  let n = sendto(sock.fd,
                 unsafeAddr data[0], data.len.cint, 0,
                 cast[ptr Sockaddr](addr addrBuf), sLen)
  if n < 0:
    if sockWouldBlock():
      return 0
    return -1
  return n.int

proc sendTo*(sock: UdpSocket, data: string,
             address: string, port: int): int =
  sock.sendTo(data.toOpenArrayByte(0, data.high), address, port)

proc send*(sock: UdpSocket, data: openArray[byte]): int =
  let n = sockSend(sock.fd, unsafeAddr data[0], data.len)
  if n < 0:
    if sockWouldBlock():
      return 0
    return -1
  return n

proc send*(sock: UdpSocket, data: string): int =
  sock.send(data.toOpenArrayByte(0, data.high))

# ── Internal read handler ────────────────────────────────────────────────────

proc handleRead(sock: UdpSocket) =
  while true:
    var sender: Sockaddr_storage
    var senderLen: SockLen = sizeof(sender).SockLen
    let n = recvfrom(sock.fd, addr sock.readBuf[0],
                     sock.readBufLen.cint, 0,
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
      return
    else:
      if sockWouldBlock():
        return
      return

# ── Server (bind + listen) ───────────────────────────────────────────────────

proc bindUdp*(loop: Loop, address: string, port: int,
              onData: OnUdpData): UdpSocket =
  let addrBuf = resolveAddr(address, port, SOCK_DGRAM)
  let fd = socket(cast[ptr Sockaddr](addr addrBuf).sa_family.cint,
                  SOCK_DGRAM, 0)
  if fd.cint < 0:
    raise newException(NetError, "socket() failed")

  setNonBlocking(fd)
  setReuseAddr(fd)

  let sLen = getSockLen(addr addrBuf)
  if bindSocket(fd, cast[ptr Sockaddr](addr addrBuf), sLen) < 0:
    sockClose(fd)
    raise newException(NetError, "bind() failed")

  let sock = UdpSocket(
    fd:         fd,
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
  let addrBuf = resolveAddr(address, port, SOCK_DGRAM)
  let fd = socket(cast[ptr Sockaddr](addr addrBuf).sa_family.cint,
                  SOCK_DGRAM, 0)
  if fd.cint < 0:
    raise newException(NetError, "socket() failed")

  setNonBlocking(fd)

  let sLen = getSockLen(addr addrBuf)
  let ret = connect(fd, cast[ptr Sockaddr](addr addrBuf), sLen)
  if ret < 0 and not sockInProgress():
    sockClose(fd)
    raise newException(NetError, "connect() failed")

  let sock = UdpSocket(
    fd:         fd,
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
