# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## This module provides UDP socket support for powpow, including both server (bind) and client (connect) modes.
## It defines the `UdpSocket` type and related procedures for sending and receiving UDP messages in an event
## loop.
##
## Backends share this single module:
##   - readiness (default): the fd is registered for {Read} and datagrams are
##     drained with `recvfrom`/`sendto` in the event callback.
##   - io_uring (`when iouEnabled`): reads use a persistent `IORING_OP_RECVMSG`
##     (sender address captured per datagram); writes use `IORING_OP_SENDMSG`
##     with one in-flight op and a bounded queue, preserving datagram boundaries.

import ../types
when not defined(windows):
  import std/posix
import ../loop
import ../loop
import common
when iouEnabled:
  import ../io/uring

# ── Types ────────────────────────────────────────────────────────────────────

when iouEnabled:
  type
    MsgHdr = object
      msg_name:       pointer
      msg_namelen:    SockLen
      msg_iov:        ptr IOVec
      msg_iovlen:     csize_t
      msg_control:    pointer
      msg_controllen: csize_t
      msg_flags:      cint

    PendingSend = object
      addrBuf: Sockaddr_storage
      hasAddr: bool
      data:    seq[byte]

type
  OnUdpData* = proc(sender: Sockaddr_storage; data: openArray[byte]) {.closure.}

  UdpSocket* = ref object
    fd*:        SocketHandle
    loop*:      Loop
    onData:     OnUdpData
    readBuf:    ptr UncheckedArray[byte]
    readBufLen: int
    when iouEnabled:
      recvToken:  uint64
      sendToken:  uint64
      fixedFd:    bool   # fd is registered in the loop's fixed-file table
      sendQueue:  seq[PendingSend]
      sendMsgHdr: MsgHdr
      sendIov:    IOVec
      sendAddr:   Sockaddr_storage
      sendData:   seq[byte]
      msgHdr:     MsgHdr
      iov:        IOVec
      senderAddr: Sockaddr_storage
      senderLen:  SockLen
      connected:  bool

# ── io_uring read/write machinery ────────────────────────────────────────────

when iouEnabled:
  proc initMsgHdr(sock: UdpSocket) =
    sock.senderLen = sizeof(sock.senderAddr).SockLen
    sock.iov = IOVec(iov_base: sock.readBuf, iov_len: sock.readBufLen.csize_t)
    sock.msgHdr = MsgHdr(
      msg_name:      addr sock.senderAddr,
      msg_namelen:   sock.senderLen,
      msg_iov:       addr sock.iov,
      msg_iovlen:    1,
    )

  proc armRecv(sock: UdpSocket) =
    if sock.recvToken != 0 or sock.fd.int < 0:
      return
    sock.recvToken = sock.loop.submitOp(proc(sqe: ptr IoUringSqe) =
        sqe.opcode = IORING_OP_RECVMSG.uint8
        sqe.fd = sock.fd.int32
        if sock.fixedFd:
          sqe.flags = IOSQE_FIXED_FILE.uint8
        sqe.paddr = cast[uint64](addr sock.msgHdr)
        sqe.len = 1
      , proc(token: uint64, res: int32, flags: uint32) =
        if sock.recvToken != token:
          # Stale completion from a previous lifecycle (closed/reused socket).
          return
        sock.recvToken = 0
        if res > 0:
          if sock.onData != nil:
            sock.onData(sock.senderAddr, sock.readBuf.toOpenArray(0, res - 1))
          if sock.recvToken == 0:
            sock.armRecv()
        elif res == 0:
          sock.armRecv()
        else:
          if res != -EAGAIN and res != -EINTR and res != -ECONNREFUSED:
            discard
          sock.armRecv())

  proc armSend(sock: UdpSocket) =
    if sock.sendToken != 0 or sock.sendQueue.len == 0 or sock.fd.int < 0:
      return
    let item = sock.sendQueue[0]
    sock.sendData = item.data
    sock.sendIov = IOVec(iov_base: addr sock.sendData[0],
                         iov_len: sock.sendData.len.csize_t)
    if item.hasAddr:
      sock.sendAddr = item.addrBuf
      sock.sendMsgHdr = MsgHdr(
        msg_name:    addr sock.sendAddr,
        msg_namelen: getSockLen(addr sock.sendAddr),
        msg_iov:     addr sock.sendIov,
        msg_iovlen:  1,
      )
    else:
      sock.sendMsgHdr = MsgHdr(
        msg_name:    nil,
        msg_namelen: 0,
        msg_iov:     addr sock.sendIov,
        msg_iovlen:  1,
      )
    sock.sendToken = sock.loop.submitOp(proc(sqe: ptr IoUringSqe) =
        sqe.opcode = IORING_OP_SENDMSG.uint8
        sqe.fd = sock.fd.int32
        if sock.fixedFd:
          sqe.flags = IOSQE_FIXED_FILE.uint8
        sqe.paddr = cast[uint64](addr sock.sendMsgHdr)
        sqe.len = 1
      , proc(token: uint64, res: int32, flags: uint32) =
        if sock.sendToken != token:
          return
        sock.sendToken = 0
        if sock.sendQueue.len > 0:
          sock.sendQueue.delete(0)
        sock.armSend())

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc close*(sock: UdpSocket) =
  if sock.fd.int < 0: return
  when iouEnabled:
    if sock.recvToken != 0:
      sock.loop.cancelOp(sock.recvToken)
      sock.recvToken = 0
    if sock.sendToken != 0:
      sock.loop.cancelOp(sock.sendToken)
      sock.sendToken = 0
    sock.sendQueue.setLen(0)
    sock.loop.unregisterFd(sock.fd.int)
    if sock.fixedFd:
      sock.loop.unregisterFixedFd(sock.fd.int)
      sock.fixedFd = false
  else:
    sock.loop.unregister(sock.fd.int)
  sockClose(sock.fd)
  sock.fd = SocketHandle(-1)
  if sock.readBuf != nil:
    releaseBuf(sock.loop, sock.readBuf)
    sock.readBuf = nil

# ── I/O ──────────────────────────────────────────────────────────────────────

proc sendTo*(sock: UdpSocket, data: openArray[byte],
             addrBuf: Sockaddr_storage): int {.inline.} =
  ## Send a datagram to an already-resolved peer address (no re-resolution).
  if data.len == 0: return 0
  when iouEnabled:
    var item: PendingSend
    item.addrBuf = addrBuf
    item.hasAddr = true
    item.data = @data
    sock.sendQueue.add(item)
    sock.armSend()
    sock.loop.submitNow()   # ensure the datagram is in flight before return
    data.len
  else:
    let sLen = getSockLen(addr addrBuf)
    let n = sendto(sock.fd,
                   unsafeAddr data[0], data.len.cint, 0,
                   cast[ptr Sockaddr](addr addrBuf), sLen)
    if n < 0:
      if sockWouldBlock():
        return 0
      return -1
    return n.int

proc sendTo*(sock: UdpSocket, data: openArray[byte],
             address: string, port: int): int {.inline.} =
  if data.len == 0: return 0
  sock.sendTo(data, sockaddrFromIp(address, port))

proc sendTo*(sock: UdpSocket, data: string,
             address: string, port: int): int {.inline.} =
  if data.len == 0: return 0
  sock.sendTo(data.toOpenArrayByte(0, data.high), address, port)

proc sendTo*(sock: UdpSocket, data: string,
             addrBuf: Sockaddr_storage): int {.inline.} =
  if data.len == 0: return 0
  sock.sendTo(data.toOpenArrayByte(0, data.high), addrBuf)

proc send*(sock: UdpSocket, data: openArray[byte]): int {.inline.} =
  if data.len == 0: return 0
  when iouEnabled:
    var item: PendingSend
    item.hasAddr = false
    item.data = @data
    sock.sendQueue.add(item)
    sock.armSend()
    sock.loop.submitNow()   # ensure the datagram is in flight before return
    data.len
  else:
    let n = sockSend(sock.fd, unsafeAddr data[0], data.len)
    if n < 0:
      if sockWouldBlock():
        return 0
      return -1
    return n

proc send*(sock: UdpSocket, data: string): int {.inline.} =
  if data.len == 0: return 0
  sock.send(data.toOpenArrayByte(0, data.high))

# ── Internal read handler (readiness backend) ────────────────────────────────

when not iouEnabled:
  proc handleRead(sock: UdpSocket) =
    while true:
      when not defined(windows):
        var sender {.noInit.}: Sockaddr_storage
        var senderLen: SockLen = sizeof(sender).SockLen
        let n = recvfrom(sock.fd, addr sock.readBuf[0],
                         sock.readBufLen.cint, 0,
                         cast[ptr Sockaddr](addr sender), addr senderLen)
        if n > 0:
          sock.onData(sender, sock.readBuf.toOpenArray(0, n - 1))
        elif n == 0:
          return
        else:
          if sockWouldBlock():
            return
          return
      else:
        # On Windows, UDP sockets are polled via select() (not WSARecv)
        # because WSARecv doesn't return the sender address. When select()
        # reports readability, recvfrom will find a datagram.
        var sender {.noInit.}: Sockaddr_storage
        var senderLen: SockLen = sizeof(sender).SockLen
        let n = recvfrom(sock.fd, addr sock.readBuf[0],
                         sock.readBufLen.cint, 0,
                         cast[ptr Sockaddr](addr sender), addr senderLen)
        if n > 0:
          sock.onData(sender, sock.readBuf.toOpenArray(0, n - 1))
        else:
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
    readBuf:    acquireBuf(loop),
    readBufLen: DefaultBufSize,
  )

  when iouEnabled:
    sock.fixedFd = loop.registerFixedFd(fd.int)
    sock.initMsgHdr()
    sock.armRecv()
  else:
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
    readBuf:    acquireBuf(loop),
    readBufLen: DefaultBufSize,
  )

  when iouEnabled:
    sock.fixedFd = loop.registerFixedFd(fd.int)
    sock.connected = true
    if onData != nil:
      sock.initMsgHdr()
      sock.armRecv()
  else:
    if onData != nil:
      loop.register(fd.int, {Read}) do (rfd: int, ev: set[EventType]):
        if Read in ev:
          sock.handleRead()

  return sock
