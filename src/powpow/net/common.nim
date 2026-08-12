# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## Common networking utilities for powpow. This module provides platform-agnostic
## socket types, error handling, and helper functions for setting socket options
## and resolving addresses. It abstracts away differences between Windows and POSIX
## APIs, allowing powpow to use a consistent interface for network operations across platforms.

when defined(windows):
  {.passC: "-D_WIN32_WINNT=0x0601".}

  # ── Winsock2 imports ──────────────────────────────────────────────────────────
  type
    SocketHandle* = cint
    SockLen* = cint
    DWORD* = uint32

    Sockaddr* {.importc: "struct sockaddr", header: "<winsock2.h>",
                pure, final.} = object
      sa_family*: cushort
      sa_data*: array[14, byte]

    Sockaddr_in* {.pure, final.} = object
      ## Note: a pure object, not an `importc` mirror of winsock's
      ## `struct sockaddr_in`. The C field `sin_addr` is an `IN_ADDR` struct,
      ## not an array — projecting it as `array[4, byte]` under `importc`
      ## makes Nim emit `(void*)sain.sin_addr` (C array decay), which fails to
      ## compile against the real header. As a pure object the layout is
      ## byte-identical (2+2+4+8) and `sin_addr` is a genuine array, so
      ## `addr sain.sin_addr` decays correctly.
      sin_family*: cushort
      sin_port*: cushort
      sin_addr*: array[4, byte]
      sin_zero*: array[8, byte]

    Sockaddr_in6* {.pure, final.} = object
      sin6_family*: cushort
      sin6_port*: cushort
      sin6_flowinfo*: int32
      sin6_addr*: array[16, byte]
      sin6_scope_id*: int32

    Sockaddr_storage* {.importc: "struct sockaddr_storage",
                        header: "<winsock2.h>", pure, final.} = object
      ss_family*: cushort
      ss_padding*: array[120, byte]

    AddrInfo* {.importc: "struct addrinfo", header: "<ws2tcpip.h>",
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
      l_onoff*: cushort
      l_linger*: cushort

    IOVec* = object
      iov_base*: pointer
      iov_len*: int

  const WSA_FLAG_OVERLAPPED = 0x01'u32

  proc wsaSocket(af, typ, protocol: cint, protocolInfo: pointer,
                 group, flags: cuint): SocketHandle {.
    importc: "WSASocketA", stdcall, dynlib: "ws2_32.dll".}

  proc socket*(af, typ, protocol: cint): SocketHandle =
    ## Create a socket with the WSA_FLAG_OVERLAPPED flag so it can be
    ## associated with an I/O completion port (the iocp backend). Plain
    ## socket() sockets are not overlapped-capable and CreateIoCompletionPort()
    ## rejects them.
    wsaSocket(af, typ, protocol, nil, 0, WSA_FLAG_OVERLAPPED)
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
  proc wsagetlasterror*(): cint {.
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

  proc getnameinfo*(sa: ptr Sockaddr, salen: SockLen,
                    host: cstring, hostlen: DWORD,
                    serv: cstring, servlen: DWORD,
                    flags: cint): cint {.
    importc: "getnameinfo", stdcall, dynlib: "ws2_32.dll".}

  proc getpeername*(s: SocketHandle, name: ptr Sockaddr,
                    namelen: ptr SockLen): cint {.
    importc: "getpeername", stdcall, dynlib: "ws2_32.dll".}

  proc inet_pton*(af: cint; src: cstring; dst: pointer): cint {.
    importc: "InetPtonA", stdcall, dynlib: "ws2_32.dll".}

  proc htons*(hostshort: cushort): cushort {.
    importc: "htons", stdcall, dynlib: "ws2_32.dll".}

  proc htonl*(hostlong: int32): int32 {.
    importc: "htonl", stdcall, dynlib: "ws2_32.dll".}

  const
    NI_NUMERICHOST* = cint(1)
    NI_MAXHOST* = 1025

  proc FormatMessageA(flags: DWORD, source: pointer, msgId: DWORD,
                      langId: DWORD, buf: var pointer, size: DWORD,
                      args: pointer): DWORD {.
    importc: "FormatMessageA", stdcall, dynlib: "kernel32".}
  proc LocalFree(p: pointer): pointer {.
    importc: "LocalFree", stdcall, dynlib: "kernel32".}

  const
    FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100
    FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
    FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200

  const
    SOCK_STREAM* = cint(1)
    SOCK_DGRAM* = cint(2)
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

  proc gai_strerrorCompat(errcode: cint): string {.inline.} =
    var buf: pointer = nil
    let n = FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER or FORMAT_MESSAGE_FROM_SYSTEM or FORMAT_MESSAGE_IGNORE_INSERTS,
      nil, errcode.DWORD, 0, buf, 0, nil)
    if n > 0:
      result = $cast[ptr UncheckedArray[char]](buf)
      discard LocalFree(buf)
    else:
      result = "getaddrinfo error (code: " & $errcode & ")"

else:
  # ── POSIX imports ────────────────────────────────────────────────────────────
  import std/posix
  export posix
  proc gai_strerrorCompat(errcode: cint): string {.inline.} =
    $gai_strerror(errcode)

  proc ioctl(fd: cint; request: culong; arg: pointer): cint {.
    importc: "ioctl", header: "<sys/ioctl.h>".}

  proc inet_pton(af: cint; src: cstring; dst: pointer): cint {.
    importc: "inet_pton", header: "<arpa/inet.h>".}

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

proc setIpv6Only*(fd: SocketHandle) =
  ## Set IPV6_V6ONLY so an IPv6 wildcard socket does not also claim IPv4
  ## (required to bind 0.0.0.0 and :: on the same port). No-op on Windows.
  when not defined(windows):
    const IPPROTO_IPV6 = cint(41)
    when defined(linux):
      const IPV6_V6ONLY = cint(26)
    elif defined(macosx) or defined(bsd):
      const IPV6_V6ONLY = cint(24)
    else:
      const IPV6_V6ONLY = cint(24)
    var one: cint = 1
    discard setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                       addr one, sizeof(one).SockLen)

# ── Address resolution ───────────────────────────────────────────────────────

proc resolveAddrAll*(address: string, port: int,
                     sockType = SOCK_STREAM, protocol = 0): seq[Sockaddr_storage] =
  ## Resolve `address:port` into ALL returned socket addresses (walks the
  ## `addrinfo` chain, so hosts with multiple A/AAAA records yield multiple
  ## candidates). The caller may try them in order for connect fallback.
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

  var it = res
  while it != nil:
    result.add(default(Sockaddr_storage))
    copyMem(addr result[^1], it.ai_addr, it.ai_addrlen)
    it = it.ai_next

proc resolveAddr*(address: string, port: int,
                  sockType = SOCK_STREAM, protocol = 0): Sockaddr_storage =
  ## Resolve `address:port` into the FIRST socket address ready for
  ## `bind`/`connect`. Works for both IPv4 and IPv6. For multi-address
  ## fallback use `resolveAddrAll`.
  result = resolveAddrAll(address, port, sockType, protocol)[0]

proc isIpAddress*(address: string): bool =
  ## True when `address` is a numeric IPv4 or IPv6 literal (no DNS needed).
  var buf: array[16, byte]
  let af = if address.find('.') >= 0: AF_INET else: AF_INET6
  inet_pton(af, address.cstring, addr buf[0]) == 1

proc sockaddrFromIp*(ip: string, port: int): Sockaddr_storage =
  ## Build a socket address from a numeric IPv4/IPv6 literal without calling
  ## getaddrinfo (which blocks on the resolver). Raises NetError otherwise.
  var res: Sockaddr_storage
  if ip.find('.') >= 0:
    var sain: Sockaddr_in
    when defined(windows):
      sain.sin_family = AF_INET.cushort
    else:
      sain.sin_family = TSa_Family(AF_INET)
    sain.sin_port = htons(port.uint16)
    if inet_pton(AF_INET, ip.cstring, addr sain.sin_addr) != 1:
      raise newException(NetError, "invalid IPv4 literal: " & ip)
    copyMem(addr res, addr sain, sizeof(sain))
  elif ip.find(':') >= 0:
    var sai6: Sockaddr_in6
    when defined(windows):
      sai6.sin6_family = AF_INET6.cushort
    else:
      sai6.sin6_family = TSa_Family(AF_INET6)
    sai6.sin6_port = htons(port.uint16)
    if inet_pton(AF_INET6, ip.cstring, addr sai6.sin6_addr) != 1:
      raise newException(NetError, "invalid IPv6 literal: " & ip)
    copyMem(addr res, addr sai6, sizeof(sai6))
  else:
    raise newException(NetError, "not an IP literal: " & ip)
  result = res

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
    result = wsagetlasterror() == WSAEWOULDBLOCK
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
  ## Scatter-gather write. On Windows there is no synchronous writev, so a loop
  ## of send() calls (one per iovec) would cost N syscalls vs 1 on POSIX — the
  ## HTTP response path routinely builds ~7 iovecs. Coalesce small writes into a
  ## single send() call instead.
  when defined(windows):
    let arr = cast[ptr UncheckedArray[IOVec]](iov)
    var total = 0
    for i in 0 ..< iovcnt:
      total += arr[i].iov_len
    if total <= 16384:
      var buf: array[16384, byte]
      var pos = 0
      for i in 0 ..< iovcnt:
        copyMem(addr buf[pos], arr[i].iov_base, arr[i].iov_len)
        pos += arr[i].iov_len
      return send(fd, addr buf[0], total.cint, 0).int
    var sent = 0
    for i in 0 ..< iovcnt:
      let n = send(fd, arr[i].iov_base, arr[i].iov_len.cint, 0).int
      if n < 0:
        if sent > 0: return sent
        return n
      sent += n
      if n < arr[i].iov_len: break
    result = sent
  else:
    result = posix.writev(fd.cint, cast[ptr posix.IOVec](iov), iovcnt.cint).int

# ── Zero-copy file transmission ───────────────────────────────────────────────

const
  SendFileChunkSize* = 65536     # fallback chunk size for non-zero-copy paths
  DefaultSendFileChunk* = 0      # 0 = let the platform decide

var sendFileScratch {.threadvar.}: ptr UncheckedArray[byte]
  ## Reusable Windows fallback read buffer: one 64KB alloc per thread instead
  ## of an alloc + dealloc per 64KB chunk of every non-zero-copy file send.

const
  O_RDONLY* = 0
  SEEK_SET* = 0
  SEEK_CUR* = 1
  SEEK_END* = 2

when defined(windows):
  const O_BINARY* = 0x8000.cint
  proc c_open(path: cstring; flags, mode: cint): cint {.
    importc: "_open", header: "<fcntl.h>".}
  proc c_lseek(fd: cint; offset: int64; whence: cint): int64 {.
    importc: "_lseeki64", header: "<io.h>".}
  proc c_read(fd: cint; buf: pointer; count: cint): cint {.
    importc: "_read", header: "<io.h>".}
  proc c_close(fd: cint): cint {.
    importc: "_close", header: "<io.h>".}
else:
  const O_BINARY* = 0.cint
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
  ## On Windows, force binary mode to prevent _read from treating
  ## 0x1A (Ctrl-Z) as EOF in binary files like videos/images.
  result = c_open(path.cstring, O_RDONLY or O_BINARY, 0)

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
    # Windows fallback: read a chunk and send it.
    # Seek to fileOff before reading so partial sends don't desync
    # the file position from fileOff (POSIX sendfile handles this
    # internally, but the read+send fallback must do it manually).
    # TODO: replace with TransmitFile when IOCP interaction is resolved.
    if sendFileScratch == nil:
      sendFileScratch = cast[ptr UncheckedArray[byte]](alloc(SendFileChunkSize))
    let buf = sendFileScratch
    let toRead = min(remaining, SendFileChunkSize.int64).cint
    discard c_lseek(fileFd.cint, fileOff, SEEK_SET)
    let n = c_read(fileFd.cint, buf, toRead)
    if n <= 0:
      return if n == 0: 0 else: -1
    let sent = send(sockFd, buf, n, 0)
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
