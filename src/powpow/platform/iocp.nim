# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
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

  SOCKET = Handle

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

proc select(nfds: cint, readfds, writefds, exceptfds: ptr FdSet,
            timeout: ptr TimeVal): cint {.
  importc: "select", stdcall, dynlib: "ws2_32.dll".}

# ── Winsock2 imports ─────────────────────────────────────────────────────────

proc wsarecv(s: SOCKET, lpBuffers: ptr WSABUF, dwBufferCount: DWORD,
             lpNumberOfBytesRecvd: var DWORD, lpFlags: var DWORD,
             lpOverlapped: pointer, lpCompletionRoutine: pointer): cint {.
    importc: "WSARecv", stdcall, dynlib: "ws2_32.dll".}

proc wsagetlasterror(): cint {.
    importc: "WSAGetLastError", stdcall, dynlib: "ws2_32.dll".}

proc getsockopt(s: SOCKET, level: cint, optname: cint,
                optval: pointer, optlen: var cint): cint {.
    importc: "getsockopt", stdcall, dynlib: "ws2_32.dll".}

const
  WSA_IO_PENDING = 997
  WSAENOTCONN    = 10057
  SOL_SOCKET_W   = 0xFFFF.cint
  SO_TYPE_W       = 3.cint
  SOCK_DGRAM_W   = 2.cint

const
  EventCapacityMin = 64
  EventCapacityMax = 16384

# ── Per-fd state ────────────────────────────────────────────────────────────

type
  IocpFdState* = object
    ol:        OVERLAPPED  # MUST be first field — kernel stores &ol, we cast back
    fd:        int
    readPosted: bool
    hasData:   bool
    readLen:   int
    readBuf:   array[16384, byte]
    udata:     pointer
    gen:       int

  IocpFdStatePtr = ptr IocpFdState

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
    listenFds:  seq[int]
    writeFds:   seq[int]
    wakeState:  IocpFdStatePtr  # pre-allocated, reused for all wake() calls
    trashStates: seq[IocpFdStatePtr]  # removed states awaiting late IOCP completions

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
  result.trashStates = @[]
  result.wakeState = cast[IocpFdStatePtr](allocShared0(sizeof(IocpFdState)))
  result.wakeState.fd = -1

proc close*(p: Platform) =
  for st in p.fdStates.values:
    deallocShared(st)
  p.fdStates.clear()
  for st in p.trashStates:
    deallocShared(st)
  p.trashStates.setLen(0)
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

proc allocFdState(fd: int, udata: pointer, gen: int): IocpFdStatePtr =
  result = cast[IocpFdStatePtr](allocShared0(sizeof(IocpFdState)))
  result.fd = fd
  result.udata = udata
  result.gen = gen

# ── Internal: post an async recv ─────────────────────────────────────────────

proc postRecv(p: Platform, state: IocpFdStatePtr) =
  if state.readPosted: return

  # Detect datagram (UDP) sockets: WSARecv doesn't return the sender
  # address, so poll them via select() instead and let handleRead call
  # recvfrom directly.
  var sockType: cint = 0
  var optLen: cint = cint(sizeof(sockType))
  if getsockopt(cast[SOCKET](state.fd), SOL_SOCKET_W, SO_TYPE_W,
                addr sockType, optLen) == 0:
    if sockType == SOCK_DGRAM_W:
      addToList(p.listenFds, state.fd)
      return

  state.readPosted = true
  state.hasData = false
  state.readLen = 0

  var wbuf = WSABUF(
    len: cint(sizeof(state.readBuf)),
    buf: addr state.readBuf[0]
  )
  var flags: DWORD = 0
  var bytesRecvd: DWORD = 0

  zeroMem(addr state.ol, sizeof(OVERLAPPED))
  let ret = wsarecv(cast[SOCKET](state.fd), addr wbuf, 1, bytesRecvd,
                    flags, addr state.ol, nil)
  if ret == 0:
    # Immediate (synchronous) completion — Windows does NOT post an
    # IOCP completion in this case, so we must record the data now.
    state.readPosted = false
    state.hasData = true
    state.readLen = bytesRecvd.int
  else:
    let err = wsagetlasterror()
    if err != WSA_IO_PENDING:
      state.readPosted = false
      if err == WSAENOTCONN:
        # Listening sockets can't WSARecv — poll them via select() instead.
        addToList(p.listenFds, state.fd)

# ── Registration ─────────────────────────────────────────────────────────────

proc add*(p: Platform, fd: int, events: set[EventType],
          edgeTriggered = false, udata: pointer = nil) =
  let gen = cast[int](udata)
  var state = allocFdState(fd, udata, gen)
  p.fdStates[fd] = state

  let res = createIoCompletionPort(cast[Handle](fd), p.iocp, nil, 0)
  if res == nil or res == INVALID_HANDLE_VALUE:
    p.fdStates.del(fd)
    deallocShared(state)
    raise newException(OSError,
      "powpow: CreateIoCompletionPort failed for fd " & $fd)

  if Read in events:
    postRecv(p, state)
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
    postRecv(p, state)
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
    postRecv(p, state)
    return n
  result = -1

# ── Polling ──────────────────────────────────────────────────────────────────

proc poll*(p: Platform, timeoutMs: int): int =
  var numRemoved: DWORD = 0
  type
    OverlappedEntry {.pure, final.} = object
      lpCompletionKey:           ULONG_PTR
      lpOverlapped:               pointer
      Internal:                   ULONG_PTR
      dwNumberOfBytesTransferred: DWORD
      hEvent:                     Handle

  const CqBufSize = 256
  var cqBuf {.noInit.}: array[CqBufSize, OverlappedEntry]

  p.count = 0

  let hasSelectFds = p.listenFds.len > 0 or p.writeFds.len > 0

  let effectiveTimeout =
    if timeoutMs < 0 and hasSelectFds:
      50.DWORD
    elif timeoutMs < 0:
      0xFFFFFFFF.DWORD
    else:
      timeoutMs.DWORD

  # ── IOCP completions (reads) ──

  let ok = getQueuedCompletionStatusEx(
    p.iocp, addr cqBuf[0], CqBufSize.DWORD,
    numRemoved, effectiveTimeout, 0)

  if ok != 0 and numRemoved > 0:
    for i in 0 ..< numRemoved.int:
      if p.count >= p.events.len: break
      let state = cast[IocpFdStatePtr](cqBuf[i].lpOverlapped)
      if state == nil: continue
      if state.fd == -1: continue  # wake() completion
      if state.fd == -2:
        # Late completion for a removed state — mark as drained.
        # Will be freed in the trash sweep below.
        state.fd = -3
        continue
      state.readLen = cqBuf[i].dwNumberOfBytesTransferred.int
      if state.ol.Internal != 0:
        # I/O error (e.g. connection reset, abort) — emit {Error}
        p.events[p.count] = PlatformEvent(
          fd: state.fd,
          events: {Error},
          udata: state.udata
        )
      elif state.readLen == 0:
        # Zero-byte completion = graceful close / EOF
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

  # ── Trash sweep: free drained removed states ──

  var ri = 0
  while ri < p.trashStates.len:
    if p.trashStates[ri].fd == -3:
      deallocShared(p.trashStates[ri])
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