# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/platform/iocp.nim — IOCP backend for Windows.
##
## Uses I/O Completion Ports for async I/O multiplexing on Windows.
## Each fd registered for {Read} gets a persistent async WSARecv posted.
## Completed reads are stored per-fd and consumed by handleClientRead.
## After consumption the read is re-posted automatically.
##
## Write events are delivered via a select() hybrid: fds registered for
## {Write} are polled with select()'s write-set each iteration. This
## matches the epoll/kqueue writability-notification model while keeping
## IOCP for the high-volume read path.

import ../types
import std/tables

# ── Win32 / Winsock2 imports ────────────────────────────────────────────────

type
  Handle = pointer
  DWORD = uint32
  ULONG_PTR = uint64
  LONG = int32
  BOOL = int32

  OVERLAPPED* {.importc: "OVERLAPPED", header: "<windows.h>",
                pure, final.} = object
    Internal:        ULONG_PTR
    InternalHigh:    ULONG_PTR
    Offset:          DWORD
    OffsetHigh:      DWORD
    hEvent:          Handle

  WSABUF {.importc: "WSABUF", header: "<winsock2.h>", pure, final.} = object
    len: int32
    buf: ptr byte

  SOCKET = uint64

  FdSet {.importc: "fd_set", header: "<winsock2.h>", pure, final.} = object
    fd_count: uint32
    fd_array: array[64, SOCKET]

  TimeVal {.importc: "struct timeval", header: "<winsock2.h>",
            pure, final.} = object
    tv_sec: LONG
    tv_usec: LONG

const
  INVALID_HANDLE_VALUE = cast[Handle](-1)

# ── Kernel32 imports ─────────────────────────────────────────────────────────

proc createIoCompletionPort(FileHandle: Handle, ExistingCompletionPort: Handle,
    CompletionKey: pointer, NumberOfConcurrentThreads: DWORD): Handle {.
    importc: "CreateIoCompletionPort", stdcall, dynlib: "kernel32".}

proc getQueuedCompletionStatusEx(CompletionPort: Handle,
    lpCompletionPortEntries: pointer, ulCount: DWORD,
    ulNumEntriesRemoved: var DWORD, dwMilliseconds: DWORD,
    fAlertable: BOOL): BOOL {.
    importc: "GetQueuedCompletionStatusEx", stdcall, dynlib: "kernel32".}

proc postQueuedCompletionStatus(CompletionPort: Handle,
    dwNumberOfBytesTransferred: DWORD, dwCompletionKey: ULONG_PTR,
    lpOverlapped: pointer): BOOL {.
    importc: "PostQueuedCompletionStatus", stdcall, dynlib: "kernel32".}

proc closeHandle(hObject: Handle): BOOL {.
    importc: "CloseHandle", stdcall, dynlib: "kernel32".}

proc getLastError(): cint {.
    importc: "GetLastError", stdcall, dynlib: "kernel32".}

proc select(nfds: cint, readfds, writefds, exceptfds: ptr FdSet,
            timeout: ptr TimeVal): cint {.
  importc: "select", stdcall, dynlib: "ws2_32.dll".}

# ── Winsock2 imports ─────────────────────────────────────────────────────────

proc wsarecv(s: SOCKET, lpBuffers: ptr WSABUF, dwBufferCount: DWORD,
             lpNumberOfBytesRecvd: ptr DWORD, lpFlags: var DWORD,
             lpOverlapped: pointer, lpCompletionRoutine: pointer): cint {.
    importc: "WSARecv", stdcall, dynlib: "ws2_32.dll".}

proc wsagetlasterror(): cint {.
    importc: "WSAGetLastError", stdcall, dynlib: "ws2_32.dll".}

proc getsockopt(s: SOCKET, level: cint, optname: cint,
                optval: pointer, optlen: var cint): cint {.
    importc: "getsockopt", stdcall, dynlib: "ws2_32.dll".}

proc setsockoptW(s: SOCKET, level, optname: cint,
                 optval: pointer, optlen: cint): cint {.
    importc: "setsockopt", stdcall, dynlib: "ws2_32.dll".}

proc wsasocketA(af, typ, protocol: cint, protocolInfo: pointer,
                group, flags: cuint): SOCKET {.
    importc: "WSASocketA", stdcall, dynlib: "ws2_32.dll".}

proc closesocketW(s: SOCKET): cint {.
    importc: "closesocket", stdcall, dynlib: "ws2_32.dll".}

proc wsAioctl(s: SOCKET, code: DWORD, inbuf: pointer, inlen: DWORD,
              outbuf: pointer, outlen: DWORD, bytesRet: var DWORD,
              overlapped: pointer, routine: pointer): cint {.
    importc: "WSAIoctl", stdcall, dynlib: "ws2_32.dll".}

const
  SIO_GET_EXTENSION_FUNCTION_POINTER = 0xC8000006'u32
  SO_UPDATE_ACCEPT_CONTEXT = cint(0x700B)
  WSA_FLAG_OVERLAPPED_W = 0x01'u32
  AF_INET_W = 2
  SOCK_STREAM_W = 1
  INVALID_SOCKET = 0xFFFFFFFFFFFFFFFF'u64
  ERROR_INVALID_PARAMETER = 87

type
  AcceptExFn = proc(listenSocket, acceptSocket: SOCKET, outputBuffer: pointer,
                    receiveDataLength, localAddressLength, remoteAddressLength: DWORD,
                    bytesReceived: ptr DWORD, overlapped: pointer): BOOL {.stdcall.}

  Guid {.pure, final.} = object
    data1: int32
    data2: int16
    data3: int16
    data4: array[8, byte]

const WSAID_ACCEPTEX = Guid(
  data1: 0xB5367DF1'i32, data2: 0xCBAC'i16, data3: 0x11CF'i16,
  data4: [0x95'u8, 0xCA'u8, 0x00'u8, 0x80'u8, 0x5F'u8, 0x48'u8, 0xA1'u8, 0x92'u8])

var gAcceptEx {.threadvar.}: AcceptExFn

proc resolveAcceptEx(s: SOCKET): bool {.gcsafe.} =
  ## Fetch the AcceptEx entry point once per thread (SIO_GET_EXTENSION_FUNCTION_POINTER).
  if gAcceptEx != nil: return true
  var bytes: DWORD = 0
  var fn: pointer = nil
  if wsAioctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, unsafeAddr WSAID_ACCEPTEX,
              sizeof(WSAID_ACCEPTEX).DWORD, addr fn, sizeof(fn).DWORD, bytes,
              nil, nil) == 0 and fn != nil:
    gAcceptEx = cast[AcceptExFn](fn)
    true
  else:
    false

const
  WSA_IO_PENDING = 997
  WSAENOTCONN    = 10057
  SOL_SOCKET_W   = 0xFFFF.cint
  SO_TYPE_W       = 0x1008.cint   # Windows SO_TYPE (0x1002 is SO_RCVBUF; 3 is SO_ACCEPTCONN)
  SO_ACCEPTCONN_W = 0x0002.cint   # Windows SO_ACCEPTCONN
  SOCK_DGRAM_W   = 2.cint

const
  EventCapacityMin = 64
  EventCapacityMax = 16384

# ── Per-fd state ────────────────────────────────────────────────────────────

type
  IocpFdState* = object
    ol:        OVERLAPPED  # MUST be first field — kernel stores &ol, we cast back
    magic:     uint32      # validity stamp; a completion whose state lacks it is stale
    fd:        int
    readPosted: bool
    hasData:   bool
    readLen:   int
    readBuf:   array[4096, byte]  # must be <= conn.readBufLen, or getReadData truncates
    udata:     pointer
    gen:       int
    isListen:  bool          # listen socket: accepts are driven by AcceptEx
    acceptSock: SOCKET       # pre-created socket for the pending AcceptEx (0 = none)
    acceptBuf: array[256, byte]  # AcceptEx output buffer (addresses + optional data)
    sockType:  cint          # cached SO_TYPE (avoids a getsockopt per WSARecv)
    sockTypeSet: bool

  IocpFdStatePtr = ptr IocpFdState

const
  IocpStateMagic = 0x494F4350'u32   # 'IOCP'

# ── Platform types ───────────────────────────────────────────────────────────

type
  PlatformEvent* = object
    fd*:     int
    events*: set[EventType]
    udata*:  pointer

  Platform* = ref object
    iocp:       Handle
    fdStates:   Table[int, IocpFdStatePtr]
    events*:    seq[PlatformEvent]
    count*:     int
    listenFds:  seq[int]      # UDP sockets polled via select() (reads need the sender address)
    writeFds:   seq[int]      # sockets with buffered writes awaiting writability
    acceptedFds: seq[(int, int)]  # (listenFd, acceptedSocket) pairs from AcceptEx
    wakeState:  IocpFdStatePtr  # pre-allocated, reused for all wake() calls
    trashStates: seq[IocpFdStatePtr]  # removed states awaiting late IOCP completions
    statePool:  seq[IocpFdStatePtr]   # drained states, safe to recycle (never freed mid-run)

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc init*(T: typedesc[Platform]): T =
  result = T()
  result.iocp = createIoCompletionPort(INVALID_HANDLE_VALUE, nil, nil, 0)
  if result.iocp == nil or result.iocp == INVALID_HANDLE_VALUE:
    raise newException(OSError, "powpow: CreateIoCompletionPort() failed")
  result.fdStates = initTable[int, IocpFdStatePtr]()
  result.events = newSeq[PlatformEvent](EventCapacityMin)
  result.listenFds = @[]
  result.writeFds = @[]
  result.acceptedFds = @[]
  result.trashStates = @[]
  result.statePool = @[]
  result.wakeState = cast[IocpFdStatePtr](allocShared0(sizeof(IocpFdState)))
  result.wakeState.fd = -1
  result.wakeState.magic = IocpStateMagic

proc close*(p: Platform) =
  # Close any sockets owned by the backend that loop.close()'s fd-watcher sweep
  # does not see: the accept socket of a pending AcceptEx, and accepted sockets
  # still queued for acceptClients.
  for st in p.fdStates.values:
    if st.isListen and st.acceptSock != 0 and st.acceptSock != INVALID_SOCKET:
      discard closesocketW(st.acceptSock)
      st.acceptSock = 0
  for (_, sock) in p.acceptedFds:
    if sock != 0 and sock != -1:
      discard closesocketW(cast[SOCKET](sock))
  p.acceptedFds.setLen(0)
  for st in p.fdStates.values:
    deallocShared(st)
  p.fdStates.clear()
  for st in p.trashStates:
    deallocShared(st)
  p.trashStates.setLen(0)
  for st in p.statePool:
    deallocShared(st)
  p.statePool.setLen(0)
  if p.wakeState != nil:
    deallocShared(p.wakeState)
    p.wakeState = nil
  if p.iocp != nil and p.iocp != INVALID_HANDLE_VALUE:
    discard closeHandle(p.iocp)
    p.iocp = nil

# ── Capacity ─────────────────────────────────────────────────────────────────

proc ensureCapacity*(p: Platform, fdCount: int) {.inline.} =
  let target = min(max(fdCount * 2, EventCapacityMin), EventCapacityMax)
  if target > p.events.len:
    p.events.setLen(target)

# ── Internal helpers ─────────────────────────────────────────────────────────

proc addToList(lst: var seq[int], fd: int) {.inline.} =
  for f in lst:
    if f == fd: return
  lst.add(fd)

proc removeFromList(lst: var seq[int], fd: int) {.inline.} =
  var i = lst.len
  while i > 0:
    dec i
    if lst[i] == fd:
      lst.del(i)
      return

proc allocFdState(p: Platform, fd: int, udata: pointer, gen: int): IocpFdStatePtr =
  ## Recycle a drained state when available — removed states are never freed
  ## mid-run (a stale completion for a freed OVERLAPPED would dereference freed
  ## memory), so a state is only recycled after its own completion was consumed.
  if p.statePool.len > 0:
    result = p.statePool.pop()
    result.fd = fd
    result.udata = udata
    result.gen = gen
    result.readPosted = false
    result.hasData = false
    result.readLen = 0
    result.isListen = false
    result.acceptSock = 0
    result.sockTypeSet = false
  else:
    result = cast[IocpFdStatePtr](allocShared0(sizeof(IocpFdState)))
    result.fd = fd
    result.udata = udata
    result.gen = gen
  result.magic = IocpStateMagic

# ── Internal: post an async recv ─────────────────────────────────────────────

proc postAcceptEx(p: Platform, state: IocpFdStatePtr) {.gcsafe.}

proc postRecv(p: Platform, state: IocpFdStatePtr): bool =
  ## Returns true when a read is set up (WSARecv posted, or a datagram/listen
  ## socket routed to its own path), false when the socket is broken (the peer
  ## reset/closed it) and the connection must be closed.
  if state.readPosted: return true

  # Datagram (UDP) sockets can't use WSARecv (no sender address) — poll them via
  # select() instead and let handleRead call recvfrom directly. The socket type
  # is cached so this check costs one getsockopt per connection, not per read.
  if not state.sockTypeSet:
    state.sockTypeSet = true
    var st: cint = 0
    var optLen: cint = cint(sizeof(st))
    if getsockopt(cast[SOCKET](state.fd), SOL_SOCKET_W, SO_TYPE_W,
                  addr st, optLen) == 0:
      state.sockType = st
  if state.sockType == SOCK_DGRAM_W:
    addToList(p.listenFds, state.fd)
    return true

  state.readPosted = true
  state.hasData = false
  state.readLen = 0

  var wbuf = WSABUF(
    len: cint(sizeof(state.readBuf)),
    buf: addr state.readBuf[0]
  )
  var flags: DWORD = 0

  zeroMem(addr state.ol, sizeof(OVERLAPPED))
  # lpNumberOfBytesRecvd is NULL because lpOverlapped is non-NULL — per the
  # WSARecv docs passing a non-NULL bytes-received pointer alongside a
  # non-NULL OVERLAPPED "may produce erroneous results". The transferred byte
  # count is read from the completion entry instead.
  let ret = wsarecv(cast[SOCKET](state.fd), addr wbuf, 1, nil,
                    flags, addr state.ol, nil)
  if ret != 0:
    # SOCKET_ERROR. If the error is WSA_IO_PENDING the operation is in flight
    # and its completion will be posted to the port — leave readPosted true.
    let err = wsagetlasterror()
    if err != WSA_IO_PENDING:
      state.readPosted = false
      if err == WSAENOTCONN:
        # WSAENOTCONN is expected on a LISTENING socket (it can't WSARecv) — drive
        # accepts via AcceptEx. But a connected socket that lost its peer ALSO
        # returns WSAENOTCONN; distinguish via SO_ACCEPTCONN and, for a connected
        # socket, signal the broken connection (return false) so the caller closes
        # it instead of silently losing the close detection.
        var acc: cint = 0
        var optLen: cint = cint(sizeof(acc))
        if getsockopt(cast[SOCKET](state.fd), SOL_SOCKET_W, SO_ACCEPTCONN_W,
                      addr acc, optLen) == 0 and acc != 0:
          state.isListen = true
          p.postAcceptEx(state)
          return true
      return false
    # Note: ret == 0 (immediate/synchronous completion) needs no special
    # handling. For a socket associated with the completion port the
    # completion packet is STILL queued, so the bytes are delivered through
    # poll() like any other read. Recording hasData here would double-consume
    # the same data AND reuse state.ol (zeroMem'd below on the re-post) while
    # the completion is still queued — corrupting the state lifecycle.
  true

proc postAcceptEx(p: Platform, state: IocpFdStatePtr) {.gcsafe.} =
  ## Post an overlapped AcceptEx on a listening socket. Accepted sockets are
  ## completed through the port (pure IOCP), so no select() is needed for
  ## accepts — the epoll-equivalent methodology.
  if state.acceptSock != 0: return  # an AcceptEx is already in flight
  if not resolveAcceptEx(cast[SOCKET](state.fd)): return
  let asock = wsasocketA(AF_INET_W, SOCK_STREAM_W, 0, nil, 0, WSA_FLAG_OVERLAPPED_W)
  if asock == INVALID_SOCKET: return
  state.acceptSock = asock
  state.isListen = true
  state.readPosted = true
  state.hasData = false
  state.readLen = 0
  zeroMem(addr state.ol, sizeof(OVERLAPPED))
  var bytes: DWORD = 0
  var ret: BOOL
  {.cast(gcsafe).}:
    ret = gAcceptEx(cast[SOCKET](state.fd), asock, addr state.acceptBuf[0], 0,
                    32.DWORD, 32.DWORD, addr bytes, addr state.ol)
  if ret == 0:
    let err = wsagetlasterror()
    if err != WSA_IO_PENDING:
      discard closesocketW(asock)
      state.acceptSock = 0
      state.readPosted = false

proc takeAcceptedSocket*(p: Platform, listenFd: int): int {.gcsafe.} =
  ## Pop one socket completed by AcceptEx for `listenFd` (0 when none).
  ## Called by acceptClients.
  for i in 0 ..< p.acceptedFds.len:
    if p.acceptedFds[i][0] == listenFd:
      result = p.acceptedFds[i][1]
      p.acceptedFds.del(i)
      return
  result = -1

# ── Registration ─────────────────────────────────────────────────────────────

proc add*(p: Platform, fd: int, events: set[EventType],
          edgeTriggered = false, udata: pointer = nil) =
  let gen = cast[int](udata)
  var state = p.fdStates.getOrDefault(fd, nil)
  if state == nil:
    state = allocFdState(p, fd, udata, gen)
    p.fdStates[fd] = state
    let res = createIoCompletionPort(cast[Handle](fd), p.iocp, nil, 0)
    if res == nil or res == INVALID_HANDLE_VALUE:
      # A socket is frequently ALREADY associated with our completion port by
      # the time it is (re)registered: a non-blocking connect arms {Write}, the
      # connect callback removes the state and re-registers the same fd for
      # {Read}; an AcceptEx-accepted socket also inherits the listener's
      # association via SO_UPDATE_ACCEPT_CONTEXT. CreateIoCompletionPort then
      # fails with ERROR_INVALID_PARAMETER (87) — expected, the socket is bound
      # to this port already. Only a genuinely invalid handle is a hard error.
      if getLastError() != ERROR_INVALID_PARAMETER:
        p.fdStates.del(fd)
        deallocShared(state)
        raise newException(OSError,
          "powpow: CreateIoCompletionPort failed for fd " & $fd)
  else:
    # Re-registration of the same fd (e.g. a non-blocking connect that arms
    # Write first and then re-registers the same socket for Read). The socket
    # is already associated with the completion port — CreateIoCompletionPort
    # must NOT be called again; just refresh the completion key/state, mirroring
    # epoll's EEXIST -> EPOLL_CTL_MOD fallback and kqueue's idempotent EV_ADD.
    state.udata = udata
    state.gen = gen

  if Read in events:
    discard postRecv(p, state)
  if Write in events:
    addToList(p.writeFds, fd)

proc remove*(p: Platform, fd: int) =
  if fd notin p.fdStates: return
  let state = p.fdStates[fd]
  p.fdStates.del(fd)
  removeFromList(p.listenFds, fd)
  removeFromList(p.writeFds, fd)
  # Always defer freeing to trashStates. If readPosted is true, a late
  # completion from closesocket-cancellation will arrive and drain the
  # trash. If readPosted is false, we post a manual completion so the
  # trash sweep can drain and free the state safely. This prevents
  # use-after-free when the IOCP queue still holds a completion whose
  # lpOverlapped points to this state.
  state.fd = -2
  p.trashStates.add(state)
  if not state.readPosted:
    discard postQueuedCompletionStatus(p.iocp, 0, 0, addr state.ol)

proc modify*(p: Platform, fd: int, events: set[EventType],
             edgeTriggered = false, udata: pointer = nil) =
  if fd notin p.fdStates: return
  let state = p.fdStates[fd]
  state.udata = udata
  state.gen = cast[int](udata)
  if Read in events and not state.readPosted:
    discard postRecv(p, state)
  if Write in events:
    addToList(p.writeFds, fd)
  else:
    removeFromList(p.writeFds, fd)

# ── Consume buffered read data ───────────────────────────────────────────────

proc getReadData*(p: Platform, fd: int,
                   buf: ptr UncheckedArray[byte],
                   bufLen: int): int =
  if fd notin p.fdStates: return -1
  let state = p.fdStates[fd]
  if state.hasData and state.readLen > 0:
    let n = if state.readLen < bufLen: state.readLen else: bufLen
    copyMem(buf, addr state.readBuf[0], n)
    state.hasData = false
    state.readLen = 0
    state.readPosted = false
    # The re-posted WSARecv may fail (the peer reset/closed the socket while we
    # were reading); the NEXT call reports EOF (0) so the connection is closed
    # instead of silently losing the close event.
    discard postRecv(p, state)
    return n
  if not state.readPosted:
    # No WSARecv in flight and nothing buffered: the connection can't be read
    # anymore (the re-post failed on a reset/closed socket). Signal EOF so the
    # caller closes it.
    return 0
  result = -1

# ── Polling ──────────────────────────────────────────────────────────────────

proc poll*(p: Platform, timeoutMs: int): int =
  var numRemoved: DWORD = 0
  type
    # OVERLAPPED_ENTRY (minwinbase.h) — NO trailing hEvent field. 32 bytes on x64.
    # The kernel writes entries at this exact stride; an extra member would
    # misalign every completion after the first (garbage lpOverlapped → crash).
    OverlappedEntry {.pure, final.} = object
      lpCompletionKey:           ULONG_PTR
      lpOverlapped:               pointer
      Internal:                   ULONG_PTR
      dwNumberOfBytesTransferred: DWORD

  const CqBufSize = 256
  var cqBuf {.noInit.}: array[CqBufSize, OverlappedEntry]

  p.count = 0

  let hasSelectFds = p.listenFds.len > 0 or p.writeFds.len > 0

  let effectiveTimeout =
    if hasSelectFds:
      # select()-based fds (datagram reads, pending writes) never produce IOCP
      # completions — select() only runs AFTER GetQueuedCompletionStatusEx
      # returns. A long IOCP wait (e.g. a multi-second timer) would starve them
      # and stall DNS/keep-alive handling. Cap the wait so select() runs
      # regularly; keep the caller's timeout when it's already shorter.
      if timeoutMs < 0: 50.DWORD
      else: min(timeoutMs, 50).DWORD
    elif timeoutMs < 0:
      0xFFFFFFFF.DWORD
    else:
      timeoutMs.DWORD

  # ── IOCP completions (reads) ──

  let ok = getQueuedCompletionStatusEx(
    p.iocp, addr cqBuf[0], CqBufSize.DWORD,
    numRemoved, effectiveTimeout, 0)

  if ok != 0 and numRemoved > 0:
    # The kernel never returns more than ulCount entries; clamp defensively so a
    # corrupt/overwritten ulNumEntriesRemoved can never drive the loop past
    # cqBuf's bounds (which would yield a garbage lpOverlapped → the crash we saw).
    let nRemoved = min(numRemoved.int, CqBufSize)
    for i in 0 ..< nRemoved:
      if p.count >= p.events.len:
        # Never drop completions: a dropped completion leaves a WSARecv's data
        # stranded (hasData never set) and the OVERLAPPED "posted" with no
        # completion to consume it — under load that desyncs the state and can
        # cascade. Grow the event array and keep going.
        p.events.setLen(max(p.events.len * 2, nRemoved + 16))
      let state = cast[IocpFdStatePtr](cqBuf[i].lpOverlapped)
      if state == nil: continue
      if state.magic != IocpStateMagic:
        # Not one of our live/recycled states — a stale or foreign completion.
        # Log once and skip so it cannot crash the loop; the state address helps
        # diagnose the source if this ever fires.
        stderr.writeLine("[iocp] stale completion lpOverlapped=",
          cast[uint](state), " i=", i, " removed=", numRemoved)
        continue
      if state.fd == -1: continue  # wake() completion
      if state.fd == -2:
        # Late completion for a removed state — mark as drained.
        # Will be recycled in the trash sweep below.
        if state.isListen and state.acceptSock != 0:
          discard closesocketW(state.acceptSock)
          state.acceptSock = 0
        state.fd = -3
        continue
      if state.fd == -3:
        # Already drained — a spurious second completion for a removed state.
        # Ignore it: the state is valid (recycled, never freed), so this is
        # safe, but it must not be dispatched as a live event.
        continue
      if state.isListen:
        # AcceptEx completion for a listening socket — a new connection is ready.
        state.readPosted = false
        let asock = state.acceptSock
        state.acceptSock = 0
        if state.ol.Internal != 0 or asock == INVALID_SOCKET:
          if asock != 0 and asock != INVALID_SOCKET:
            discard closesocketW(asock)
          p.postAcceptEx(state)
          continue
        # Finalize the accepted socket (SO_UPDATE_ACCEPT_CONTEXT) and queue it for
        # acceptClients. Emit {Read} so the listen callback drains the queue.
        var lsock = cast[SOCKET](state.fd)
        discard setsockoptW(asock, SOL_SOCKET_W, SO_UPDATE_ACCEPT_CONTEXT,
                            addr lsock, sizeof(lsock).cint)
        p.acceptedFds.add((state.fd, asock.int))
        if p.count < p.events.len:
          p.events[p.count] = PlatformEvent(fd: state.fd, events: {Read}, udata: state.udata)
          inc p.count
        p.postAcceptEx(state)
        continue
      state.readLen = cqBuf[i].dwNumberOfBytesTransferred.int
      if state.ol.Internal != 0:
        # I/O error (e.g. connection reset, abort) — emit {Error}. The in-flight
        # WSARecv has completed, so no further completion will reference this
        # state: clear readPosted so a close() posts the drain completion and
        # the state is recycled instead of leaking in the trash list.
        state.readPosted = false
        p.events[p.count] = PlatformEvent(
          fd: state.fd,
          events: {Error},
          udata: state.udata
        )
      elif state.readLen == 0:
        # Zero-byte completion = graceful close / EOF. Same readPosted reset as
        # above — the WSARecv is done, so the state must be drainable on close.
        state.readPosted = false
        p.events[p.count] = PlatformEvent(
          fd: state.fd,
          events: {Read, Hup},
          udata: state.udata
        )
      else:
        state.hasData = true
        p.events[p.count] = PlatformEvent(
          fd: state.fd,
          events: {Read},
          udata: state.udata
        )
      inc p.count

  # ── Trash sweep: recycle drained removed states ──

  var ri = 0
  while ri < p.trashStates.len:
    if p.trashStates[ri].fd == -3:
      # The state's own completion (or its drain completion) was consumed — no
      # further completion can reference it. Recycle it. States are NEVER freed
      # mid-run: a late completion for a removed state must always be able to
      # dereference a live IocpFdState (even a recycled one), otherwise the
      # completion loop crashes on freed memory. Freed only at platform.close().
      p.statePool.add(p.trashStates[ri])
      p.trashStates.del(ri)
    else:
      inc ri

  # ── select() for listen sockets (read) + write-pending sockets (write) ──

  if hasSelectFds:
    var readSet: FdSet
    var writeSet: FdSet
    readSet.fd_count = 0
    writeSet.fd_count = 0
    var tv: TimeVal
    tv.tv_sec = 0
    tv.tv_usec = 0

    for fd in p.listenFds:
      if readSet.fd_count >= 64: break
      readSet.fd_array[readSet.fd_count] = cast[SOCKET](fd)
      inc readSet.fd_count

    for fd in p.writeFds:
      if writeSet.fd_count >= 64: break
      writeSet.fd_array[writeSet.fd_count] = cast[SOCKET](fd)
      inc writeSet.fd_count

    let rFdset = if readSet.fd_count > 0: addr readSet else: nil
    let wFdset = if writeSet.fd_count > 0: addr writeSet else: nil

    let selRet = select(0, rFdset, wFdset, nil, addr tv)
    if selRet > 0:
      # Readable listen sockets → {Read}
      for i in 0..<readSet.fd_count.int:
        if p.count >= p.events.len: break
        let fd = cast[int](readSet.fd_array[i])
        if fd in p.fdStates:
          p.events[p.count] = PlatformEvent(
            fd: fd,
            events: {Read},
            udata: p.fdStates[fd].udata
          )
          inc p.count
      # Writable sockets → {Write}
      for i in 0..<writeSet.fd_count.int:
        if p.count >= p.events.len: break
        let fd = cast[int](writeSet.fd_array[i])
        if fd in p.fdStates:
          p.events[p.count] = PlatformEvent(
            fd: fd,
            events: {Write},
            udata: p.fdStates[fd].udata
          )
          inc p.count

  result = p.count

# ── Wake support ─────────────────────────────────────────────────────────────

proc wake*(p: Platform) =
  discard postQueuedCompletionStatus(p.iocp, 0, 0, addr p.wakeState.ol)