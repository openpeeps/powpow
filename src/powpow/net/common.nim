# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## Common networking utilities for powpow. This module provides platform-agnostic
## socket types, error handling, and helper functions for setting socket options
## and resolving addresses. It abstracts away differences between Windows and POSIX
## APIs, allowing powpow to use a consistent interface for network operations across platforms.

when defined(windows):
  # ── Winsock2 imports ──────────────────────────────────────────────────────────
  type
    cint* = int32
    SocketHandle* = cint
    SockLen* = cint

    Sockaddr* {.importc: "struct sockaddr", header: "<winsock2.h>",
                pure, final.} = object
      sa_family: cushort
      sa_data: array[14, byte]

    Sockaddr_in* {.importc: "struct sockaddr_in", header: "<winsock2.h>",
                   pure, final.} = object
      sin_family: cushort
      sin_port: cushort
      sin_addr: array[4, byte]
      sin_zero: array[8, byte]

    Sockaddr_in6* {.importc: "struct sockaddr_in6", header: "<winsock2.h>",
                    pure, final.} = object
      sin6_family: cushort
      sin6_port: cushort
      sin6_flowinfo: int32
      sin6_addr: array[16, byte]
      sin6_scope_id: int32

    Sockaddr_storage* {.importc: "struct sockaddr_storage",
                        header: "<winsock2.h>", pure, final.} = object
      ss_family: cushort
      ss_padding: array[120, byte]

    AddrInfo* {.importc: "struct addrinfo", header: "<winsock2.h>",
                pure, final.} = object
      ai_flags: cint
      ai_family: cint
      ai_socktype: cint
      ai_protocol: cint
      ai_addrlen: SockLen
      ai_canonname: cstring
      ai_addr: ptr Sockaddr
      ai_next: ptr AddrInfo

    TLinger* {.importc: "struct linger", header: "<winsock2.h>",
               pure, final.} = object
      l_onoff: cushort
      l_linger: cushort

    IOVec* = object
      iov_base: pointer
      iov_len: int

  proc socket*(af, typ, protocol: cint): SocketHandle {.
    importc: "socket", stdcall, dynlib: "ws2_32.dll".}
  proc bindSocket*(s: SocketHandle, name: pointer, namelen: SockLen): cint {.
    importc: "bind", stdcall, dynlib: "ws2_32.dll".}
  proc listen*(s: SocketHandle, backlog: cint): cint {.
    importc: "listen", stdcall, dynlib: "ws2_32.dll".}
  proc accept*(s: SocketHandle, addrP: pointer, addrlen: ptr SockLen): SocketHandle {.
    importc: "accept", stdcall, dynlib: "ws2_32.dll".}
  proc connect*(s: SocketHandle, name: pointer, namelen: SockLen): cint {.
    importc: "connect", stdcall, dynlib: "ws2_32.dll".}
  proc send*(s: SocketHandle, buf: pointer, len: cint, flags: cint): cint {.
    importc: "send", stdcall, dynlib: "ws2_32.dll".}
  proc recv*(s: SocketHandle, buf: pointer, len: cint, flags: cint): cint {.
    importc: "recv", stdcall, dynlib: "ws2_32.dll".}
  proc closesocket*(s: SocketHandle): cint {.
    importc: "closesocket", stdcall, dynlib: "ws2_32.dll".}
  proc shutdown*(s: SocketHandle, how: cint): cint {.
    importc: "shutdown", stdcall, dynlib: "ws2_32.dll".}
  proc setsockopt*(s: SocketHandle, level, optname: cint,
                   optval: pointer, optlen: SockLen): cint {.
    importc: "setsockopt", stdcall, dynlib: "ws2_32.dll".}
  proc getsockopt*(s: SocketHandle, level, optname: cint,
                   optval: pointer, optlen: ptr SockLen): cint {.
    importc: "getsockopt", stdcall, dynlib: "ws2_32.dll".}
  proc ioctlsocket*(s: SocketHandle, cmd: int32, argp: pointer): cint {.
    importc: "ioctlsocket", stdcall, dynlib: "ws2_32.dll".}
  proc sendto*(s: SocketHandle, buf: pointer, len: cint, flags: cint,
               to: ptr Sockaddr, tolen: SockLen): cint {.
    importc: "sendto", stdcall, dynlib: "ws2_32.dll".}
  proc recvfrom*(s: SocketHandle, buf: pointer, len: cint, flags: cint,
                 fromAddr: ptr Sockaddr, fromlen: ptr SockLen): cint {.
    importc: "recvfrom", stdcall, dynlib: "ws2_32.dll".}
  proc wsagetlasterror(): cint {.
    importc: "WSAGetLastError", stdcall, dynlib: "ws2_32.dll".}
  proc wsaStartup(wVersionRequested: int16, lpWSAData: pointer): cint {.
    importc: "WSAStartup", stdcall, dynlib: "ws2_32.dll".}
  proc wsaCleanup(): cint {.
    importc: "WSACleanup", stdcall, dynlib: "ws2_32.dll".}
  proc getaddrinfo*(node: cstring, service: cstring,
                    hints: ptr AddrInfo,
                    res: var ptr AddrInfo): cint {.
    importc: "getaddrinfo", stdcall, dynlib: "ws2_32.dll".}
  proc freeaddrinfo*(res: ptr AddrInfo) {.
    importc: "freeaddrinfo", stdcall, dynlib: "ws2_32.dll".}
  proc gai_strerror(errcode: cint): cstring {.
    importc: "gai_strerrorA", stdcall, dynlib: "ws2_32.dll".}

  const
    SOCK_STREAM* = cint(1)
    SOL_SOCKET* = cint(0xFFFF)
    SO_REUSEADDR* = cint(0x0004)
    SO_LINGER* = cint(0x0080)
    SO_ERROR* = cint(0x1007)
    IPPROTO_TCP* = cint(6)
    TCP_NODELAY* = cint(0x0001)
    AF_UNSPEC* = cint(0)
    AF_INET* = cint(2)
    AF_INET6* = cint(23)
    AI_PASSIVE* = cint(0x0001)
    SOMAXCONN* = cint(0x7FFFFFFF)
    FIONBIO* = -2147195266'i32
    WSAEWOULDBLOCK* = 10035
    WSAEINPROGRESS* = 10036
    WSAENETDOWN* = 10050
    WSAECONNRESET* = 10054
    WSAESHUTDOWN* = 10058

  proc gai_strerrorW(errcode: cint): cstring {.
    importc: "gai_strerrorW", stdcall, dynlib: "ws2_32.dll".}

  proc gai_strerrorCompat(errcode: cint): cstring {.inline.} =
    when defined(cpu64):
      result = gai_strerrorW(errcode)
    else:
      result = gai_strerror(errcode)

else:
  # ── POSIX imports ────────────────────────────────────────────────────────────
  import std/posix
  export posix
  proc gai_strerrorCompat(errcode: cint): cstring {.inline.} =
    gai_strerror(errcode)

  proc ioctl(fd: cint; request: culong; arg: pointer): cint {.
    importc: "ioctl", header: "<sys/ioctl.h>".}

  when defined(macosx) or defined(bsd):
    const FIONBIO = 0x8004667E.culong
  else:
    const FIONBIO = 0x5421.culong

  const UNIX_PATH_MAX* = 107

# ── Platform-independent socket functions ───────────────────────────────────

proc initNet*() =
  ## Initialize networking. Safe to call multiple times.
  when defined(windows):
    var data: array[512, byte]  # WSADATA
    discard wsaStartup(0x0202, addr data[0])
  else:
    signal(SIGPIPE, SIG_IGN)

# Auto-init on module load
initNet()

# ── Errors ───────────────────────────────────────────────────────────────────

type
  NetError* = object of CatchableError

proc lastSocketError*(): cint {.inline.} =
  ## Get the last socket error (platform-agnostic).
  when defined(windows):
    result = wsagetlasterror()
  else:
    result = errno

# ── Socket options ───────────────────────────────────────────────────────────

proc setNonBlocking*(fd: SocketHandle) =
  ## Put a socket into non-blocking mode using a single ioctl syscall.
  when defined(windows):
    var mode: int32 = 1
    if ioctlsocket(fd, FIONBIO, addr mode) < 0:
      raise newException(NetError, "ioctlsocket FIONBIO failed")
  else:
    var one: cint = 1
    if ioctl(fd.cint, FIONBIO, addr one) < 0:
      raise newException(NetError, "ioctl FIONBIO failed")

proc setReuseAddr*(fd: SocketHandle) =
  ## Enable SO_REUSEADDR on a socket.
  var val: cint = 1
  if setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                addr val, sizeof(val).SockLen) < 0:
    raise newException(NetError, "setsockopt SO_REUSEADDR failed")

proc setReusePort*(fd: SocketHandle) =
  ## Enable SO_REUSEPORT on a socket (macOS/Linux). No-op on Windows.
  when not defined(windows):
    var val: cint = 1
    if setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
                  addr val, sizeof(val).SockLen) < 0:
      raise newException(NetError, "setsockopt SO_REUSEPORT failed")

proc setTcpNoDelay*(fd: SocketHandle) =
  ## Disable Nagle's algorithm for lower latency.
  ## Silently ignores errors (e.g. on AF_UNIX sockets where TCP_NODELAY
  ## is not applicable).
  var val: cint = 1
  discard setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                     addr val, sizeof(val).SockLen)

proc setTcpCork*(fd: SocketHandle, enable: bool) =
  ## Enable or disable TCP corking (TCP_CORK on Linux, TCP_NOPUSH on macOS/BSD).
  ## No-op on Windows and other unsupported platforms.
  when defined(linux):
    const TCP_CORK = cint(3)
    var val: cint = if enable: 1 else: 0
    discard setsockopt(fd, IPPROTO_TCP, TCP_CORK,
                       addr val, sizeof(val).SockLen)
  elif defined(macosx) or defined(bsd):
    const TCP_NOPUSH = cint(4)
    var val: cint = if enable: 1 else: 0
    discard setsockopt(fd, IPPROTO_TCP, TCP_NOPUSH,
                       addr val, sizeof(val).SockLen)

# ── Address resolution ───────────────────────────────────────────────────────

proc resolveAddr*(address: string, port: int,
                  sockType = SOCK_STREAM, protocol = 0): Sockaddr_storage =
  ## Resolve `address:port` into a `Sockaddr_storage` ready for `bind`/`connect`.
  ## Works for both IPv4 and IPv6.
  var hints: AddrInfo
  hints.ai_family   = AF_UNSPEC
  hints.ai_socktype = sockType
  hints.ai_flags    = AI_PASSIVE

  var res: ptr AddrInfo
  let err = getaddrinfo(address, cstring($port), addr hints, res)
  if err != 0:
    raise newException(NetError,
      "getaddrinfo failed: " & $gai_strerrorCompat(err))
  defer: freeaddrinfo(res)

  copyMem(addr result, res.ai_addr, res.ai_addrlen)

proc getSockLen*(addrBuf: ptr Sockaddr_storage): SockLen {.inline.} =
  ## Return the correct socklen for the address family.
  let family = cast[ptr Sockaddr](addrBuf).sa_family
  if family == AF_INET.cushort:
    result = sizeof(Sockaddr_in).SockLen
  elif family == AF_INET6.cushort:
    result = sizeof(Sockaddr_in6).SockLen
  else:
    result = sizeof(Sockaddr_storage).SockLen

# ── Platform error helpers ─────────────────────────────────────────────────

proc sockWouldBlock*(): bool {.inline.} =
  when defined(windows):
    result = wsagetlasterror() == WSAEWOULDBLOCK
  else:
    result = errno == EAGAIN or errno == EWOULDBLOCK

proc sockInterrupted*(): bool {.inline.} =
  when defined(windows):
    result = false
  else:
    result = errno == EINTR

proc sockInProgress*(): bool {.inline.} =
  when defined(windows):
    result = wsagetlasterror() == WSAEINPROGRESS
  else:
    result = errno == EINPROGRESS

# ── Platform-agnostic read/write helpers ────────────────────────────────────

proc sockRecv*(fd: SocketHandle, buf: pointer, bufLen: int): int {.inline.} =
  ## Read from a socket. Returns bytes read, 0 on EOF, negative on error.
  result = recv(fd, buf, bufLen.cint, 0).int

proc sockSend*(fd: SocketHandle, buf: pointer, len: int): int {.inline.} =
  ## Write to a socket. Returns bytes written, negative on error.
  result = send(fd, buf, len.cint, 0).int

proc sockClose*(fd: SocketHandle) {.inline.} =
  ## Close a socket.
  when defined(windows):
    discard closesocket(fd)
  else:
    discard posix.close(fd)

proc sockShutdown*(fd: SocketHandle, how: cint) {.inline.} =
  ## Shut down part of a full-duplex connection.
  when defined(windows):
    const SD_SEND = cint(1)
    discard shutdown(fd, how)
  else:
    discard posix.shutdown(fd, how)

proc sockWritev*(fd: SocketHandle, iov: ptr IOVec, iovcnt: int): int {.inline.} =
  ## Scatter-gather write. On Windows, concatenates buffers and calls send.
  when defined(windows):
    let arr = cast[ptr UncheckedArray[IOVec]](iov)
    var total = 0
    for i in 0 ..< iovcnt:
      let n = send(fd, arr[i].iov_base, arr[i].iov_len.cint, 0).int
      if n < 0:
        if total > 0: return total
        return n
      total += n
      if n < arr[i].iov_len: break
    result = total
  else:
    result = posix.writev(fd.cint, cast[ptr posix.IOVec](iov), iovcnt.cint).int

# ── Zero-copy file transmission ───────────────────────────────────────────────

const
  SendFileChunkSize* = 65536     # fallback chunk size for non-zero-copy paths
  DefaultSendFileChunk* = 0      # 0 = let the platform decide

const
  O_RDONLY* = 0
  SEEK_SET* = 0
  SEEK_CUR* = 1
  SEEK_END* = 2

when defined(windows):
  proc c_open(path: cstring; flags, mode: cint): cint {.
    importc: "_open", header: "<fcntl.h>".}
  proc c_lseek(fd: cint; offset: int64; whence: cint): int64 {.
    importc: "_lseeki64", header: "<io.h>".}
  proc c_read(fd: cint; buf: pointer; count: cint): cint {.
    importc: "_read", header: "<io.h>".}
  proc c_close(fd: cint): cint {.
    importc: "_close", header: "<io.h>".}
else:
  proc c_open(path: cstring; flags, mode: cint): cint =
    posix.open(path, flags, mode).cint
  proc c_lseek(fd: cint; offset: int64; whence: cint): int64 =
    posix.lseek(fd, offset, whence)
  proc c_read(fd: cint; buf: pointer; count: cint): cint =
    posix.read(fd, buf, count).cint
  proc c_close(fd: cint): cint =
    posix.close(fd).cint

proc openFileRead*(path: string): int =
  ## Open a file for reading. Returns fd or -1 on error.
  result = c_open(path.cstring, O_RDONLY, 0)

proc getFileSize*(fd: int): int64 =
  ## Get file size from an open fd. Returns -1 on error.
  let cur = c_lseek(fd.cint, 0, SEEK_CUR)
  if cur < 0: return -1
  let sz = c_lseek(fd.cint, 0, SEEK_END)
  if sz >= 0:
    discard c_lseek(fd.cint, cur, SEEK_SET)
  sz

proc closeFile*(fd: int) {.inline.} =
  ## Close a file descriptor.
  discard c_close(fd.cint)

proc readFile*(fd: int; buf: ptr UncheckedArray[byte]; len: int): int64 =
  ## Read up to len bytes from a file. Returns bytes read, 0 on EOF, -1 on error.
  result = c_read(fd.cint, buf, len.cint).int64

proc seekFile*(fd: int; offset: int64): int64 =
  ## Seek to an absolute position in a file. Returns new position or -1 on error.
  result = c_lseek(fd.cint, offset, SEEK_SET)

proc sendFileChunk*(sockFd: SocketHandle; fileFd: int;
                    fileOff: var int64; remaining: var int64): int64 =
  ## Send file data to a socket using zero-copy when available.
  ## Updates fileOff and remaining. Returns bytes sent,
  ## 0 on EAGAIN (caller should retry when socket is writable),
  ## -1 on hard error.
  when defined(linux):
    proc sf(out_fd, in_fd: cint; offset: ptr int64; count: csize_t): cint {.
      importc: "sendfile", header: "<sys/sendfile.h>".}
    var off = fileOff
    let n = cast[int64](sf(sockFd.cint, fileFd.cint,
                          addr off, remaining.csize_t))
    if n < 0:
      let e = errno
      if e == EAGAIN or e == EWOULDBLOCK: return 0
      return -1
    fileOff = off
    remaining -= n
    result = n
  elif defined(macosx) or defined(bsd):
    proc sf(in_fd, out_fd: cint; offset: int64; len: var int64;
             hdtr: pointer; flags: cint): cint {.
      importc: "sendfile", header: "<sys/socket.h>".}
    var sent = remaining
    let ret = sf(fileFd.cint, sockFd.cint, fileOff, sent, nil, 0)
    if ret < 0:
      let e = errno
      if e == EAGAIN or e == EWOULDBLOCK:
        # macOS may have sent partial data even on EAGAIN
        if sent > 0:
          fileOff += sent
          remaining -= sent
          result = sent
        else:
          result = 0
        return
      return -1
    fileOff += sent
    remaining -= sent
    result = sent
  else:
    # Windows fallback: read a chunk and send it
    var buf = cast[ptr UncheckedArray[byte]](alloc(SendFileChunkSize))
    let toRead = min(remaining, SendFileChunkSize)
    let n = c_read(fileFd.cint, buf,
                   if toRead > SendFileChunkSize: SendFileChunkSize.cint else: toRead.cint)
    if n <= 0:
      dealloc(buf)
      return if n == 0: 0 else: -1
    let sent = send(sockFd, buf, n, 0)
    dealloc(buf)
    if sent < 0:
      let e = wsagetlasterror()
      if e == WSAEWOULDBLOCK: return 0
      return -1
    fileOff += sent
    remaining -= sent
    result = sent

# ── Buffer ───────────────────────────────────────────────────────────────────

const DefaultBufSize* = 4096
  ## Default read buffer size per connection.
