## powpow/net/common.nim — Shared networking helpers.
##
## Non-blocking socket setup, address resolution, and shared types.

import std/posix
export posix

# ── Signal safety ────────────────────────────────────────────────────────────
# Ignore SIGPIPE globally — prevents CPU spin when send() hits a closed socket.
# On macOS MSG_NOSIGNAL doesn't exist; on Linux it's a safety net.
proc initNet*() =
  ## Initialize networking. Call once at startup. Safe to call multiple times.
  signal(SIGPIPE, SIG_IGN)

# Auto-init on module load
initNet()

# ── Errors ───────────────────────────────────────────────────────────────────

type
  NetError* = object of CatchableError

# ── Socket options ───────────────────────────────────────────────────────────

proc setNonBlocking*(fd: SocketHandle) =
  ## Put a socket into non-blocking mode.
  let flags = fcntl(fd.cint, F_GETFL, 0)
  if flags < 0:
    raise newException(NetError, "fcntl F_GETFL failed")
  if fcntl(fd.cint, F_SETFL, flags or O_NONBLOCK) < 0:
    raise newException(NetError, "fcntl F_SETFL O_NONBLOCK failed")

proc setReuseAddr*(fd: SocketHandle) =
  ## Enable SO_REUSEADDR on a socket.
  var val: cint = 1
  if setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                addr val, sizeof(val).SockLen) < 0:
    raise newException(NetError, "setsockopt SO_REUSEADDR failed")

proc setReusePort*(fd: SocketHandle) =
  ## Enable SO_REUSEPORT on a socket (macOS/Linux).
  var val: cint = 1
  if setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
                addr val, sizeof(val).SockLen) < 0:
    raise newException(NetError, "setsockopt SO_REUSEPORT failed")

proc setTcpNoDelay*(fd: SocketHandle) =
  ## Disable Nagle's algorithm for lower latency.
  var val: cint = 1
  if setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                addr val, sizeof(val).SockLen) < 0:
    raise newException(NetError, "setsockopt TCP_NODELAY failed")

proc setTcpCork*(fd: SocketHandle, enable: bool) =
  ## Enable or disable TCP corking (TCP_CORK on Linux, TCP_NOPUSH on macOS/BSD).
  ## When corked, the kernel buffers small writes until uncorked, then sends
  ## them as a single segment — reducing packet count for header+body responses.
  ## No-op on platforms without cork support.
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
                  sockType = SOCK_STREAM, protocol = 0): SockAddr_storage =
  ## Resolve `address:port` into a `SockAddr_storage` ready for `bind`/`connect`.
  ## Works for both IPv4 and IPv6.
  var hints: AddrInfo
  hints.ai_family   = AF_UNSPEC
  hints.ai_socktype = sockType.cint
  hints.ai_flags    = AI_PASSIVE

  var res: ptr AddrInfo
  let err = getaddrinfo(address, cstring($port), addr hints, res)
  if err != 0:
    raise newException(NetError,
      "getaddrinfo failed: " & $gai_strerror(err))
  defer: freeaddrinfo(res)

  copyMem(addr result, res.ai_addr, res.ai_addrlen.int)

proc getSockLen*(addrBuf: ptr Sockaddr_storage): SockLen =
  ## Return the correct socklen for the address family.
  let family = cast[ptr Sockaddr](addrBuf).sa_family
  if family.cint == AF_INET:
    result = sizeof(Sockaddr_in).SockLen
  elif family.cint == AF_INET6:
    result = sizeof(Sockaddr_in6).SockLen
  else:
    result = sizeof(Sockaddr_storage).SockLen

# ── Buffer ───────────────────────────────────────────────────────────────────

const DefaultBufSize* = 4096
  ## Default read buffer size per connection.
