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

import ../types
import std/tables

# ── Win32 / Winsock2 imports ────────────────────────────────────────────────

type
  Handle = pointer
  DWORD = uint32
  ULONG_PTR = uint64
  LONG = int32
  BOOL = int32
  UINT = int32

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

const
  INVALID_HANDLE_VALUE = cast[Handle](-1)
  WAIT_TIMEOUT = 258

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

# ── Winsock2 imports ─────────────────────────────────────────────────────────

proc wsasocketW(af: cint, typ: cint, protocol: cint,
                lpProtocolInfo: pointer, g: DWORD,
                dwFlags: DWORD): SOCKET {.
    importc: "WSASocketW", stdcall, dynlib: "ws2_32.dll".}

proc wsarecv(s: SOCKET, lpBuffers: ptr WSABUF, dwBufferCount: DWORD,
             lpNumberOfBytesRecvd: var DWORD, lpFlags: var DWORD,
             lpOverlapped: pointer, lpCompletionRoutine: pointer): cint {.
    importc: "WSARecv", stdcall, dynlib: "ws2_32.dll".}

proc wsasend(s: SOCKET, lpBuffers: ptr WSABUF, dwBufferCount: DWORD,
             lpNumberOfBytesSent: var DWORD, dwFlags: DWORD,
             lpOverlapped: pointer, lpCompletionRoutine: pointer): cint {.
    importc: "WSASend", stdcall, dynlib: "ws2_32.dll".}

proc wsagetlasterror(): cint {.
    importc: "WSAGetLastError", stdcall, dynlib: "ws2_32.dll".}

const
  WSA_IO_PENDING = 997
  WSAECONNRESET = 10054
  WSAEWOULDBLOCK = 10035

const
  EventCapacityMin = 64
  EventCapacityMax = 16384

# ── Completion packet ────────────────────────────────────────────────────────

type
  IocpOpKind = enum
    opRead
    opWrite
    opShutdown

  OverlappedExt {.pure, final.} = object
    ol:        OVERLAPPED
    fd:        int
    kind:      IocpOpKind
    udata:     pointer
    gen:       int

  OverlappedExtPtr = ptr OverlappedExt

  IocpFdState = object
    readExt:   OverlappedExtPtr
    readPosted: bool
    udata:     pointer
    gen:       int
    readBuf:   array[16384, byte]
    readLen:   int
    hasData:   bool

# ── Platform types ───────────────────────────────────────────────────────────

type
  PlatformEvent* = object
    fd*:     int
    events*: set[EventType]
    udata*:  pointer

  Platform* = ref object
    iocp:       Handle
    fdStates:   Table[int, IocpFdState]
    events*:    seq[PlatformEvent]
    count*:     int
    extPool:    seq[OverlappedExtPtr]

proc allocExt(): OverlappedExtPtr =
  result = cast[OverlappedExtPtr](allocShared0(sizeof(OverlappedExt)))

proc freeExt(ext: OverlappedExtPtr) =
  deallocShared(ext)

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc init*(T: typedesc[Platform]): T =
  result = T()
  result.iocp = createIoCompletionPort(INVALID_HANDLE_VALUE, nil, nil, 0)
  if result.iocp == nil or result.iocp == INVALID_HANDLE_VALUE:
    raise newException(OSError, "powpow: CreateIoCompletionPort() failed")
  result.fdStates = initTable[int, IocpFdState]()
  result.events = newSeq[PlatformEvent](EventCapacityMin)
  result.extPool = @[]

proc close*(p: Platform) =
  for ext in p.extPool:
    freeExt(ext)
  p.extPool.setLen(0)
  p.fdStates.clear()
  if p.iocp != nil and p.iocp != INVALID_HANDLE_VALUE:
    discard closeHandle(p.iocp)
    p.iocp = nil

# ── Capacity ─────────────────────────────────────────────────────────────────

proc ensureCapacity*(p: Platform, fdCount: int) =
  let target = min(max(fdCount * 2, EventCapacityMin), EventCapacityMax)
  if target > p.events.len:
    p.events.setLen(target)

# ── Internal: post an async recv ─────────────────────────────────────────────

proc postRecv(p: Platform, fd: int) =
  if fd notin p.fdStates: return
  var state = addr p.fdStates[fd]
  if state.readPosted: return

  state.readPosted = true
  state.hasData = false
  state.readLen = 0

  var ext = allocExt()
  ext.fd = fd
  ext.kind = opRead
  ext.udata = state.udata
  ext.gen = state.gen
  p.extPool.add(ext)

  var wbuf = WSABUF(
    len: cint(sizeof(state.readBuf)),
    buf: addr state.readBuf[0]
  )
  var flags: DWORD = 0
  var bytesRecvd: DWORD = 0

  let ret = wsarecv(cast[SOCKET](fd), addr wbuf, 1, bytesRecvd,
                    flags, addr ext.ol, nil)
  if ret == 0:
    # Completed immediately
    discard getQueuedCompletionStatusEx(p.iocp, nil, 0, cast[var DWORD](0), 0, 0)
  elif wsagetlasterror() != WSA_IO_PENDING:
    state.readPosted = false
    # Socket error — the fd watcher will handle it on the next poll

# ── Registration ─────────────────────────────────────────────────────────────

proc add*(p: Platform, fd: int, events: set[EventType],
          edgeTriggered = false, udata: pointer = nil) =
  ## Register interest in `events` on `fd`.
  ## On IOCP, `edgeTriggered` is always implicit — we post one-shot reads
  ## that must be re-posted after each completion.
  let gen = cast[int](udata)
  var state = IocpFdState(
    udata: udata,
    gen: gen,
    readPosted: false,
    hasData: false
  )
  p.fdStates[fd] = state

  # Associate socket with the IOCP handle
  let result = createIoCompletionPort(cast[Handle](fd),
                                       p.iocp, nil, 0)
  if result == nil or result == INVALID_HANDLE_VALUE:
    p.fdStates.del(fd)
    raise newException(OSError,
      "powpow: CreateIoCompletionPort failed for fd " & $fd)

  if Read in events:
    postRecv(p, fd)

proc remove*(p: Platform, fd: int) =
  ## Remove all event registrations for `fd`.
  if fd notin p.fdStates: return
  # Free any outstanding ext for this fd
  var i = 0
  while i < p.extPool.len:
    if p.extPool[i].fd == fd:
      freeExt(p.extPool[i])
      p.extPool.del(i)
    else:
      inc i
  p.fdStates.del(fd)

proc modify*(p: Platform, fd: int, events: set[EventType],
             edgeTriggered = false, udata: pointer = nil) =
  ## Change the event interests for an already-registered `fd`.
  if fd notin p.fdStates: return
  var state = addr p.fdStates[fd]
  state.udata = udata
  state.gen = cast[int](udata)
  if Read in events and not state.readPosted:
    postRecv(p, fd)

# ── Consume buffered read data ───────────────────────────────────────────────

proc getReadData*(p: Platform, fd: int,
                   buf: ptr UncheckedArray[byte],
                   bufLen: int): int =
  ## Read buffered data from a completed IOCP read.
  ## On Unix backends this calls recv() directly; on IOCP it returns
  ## data that was already read asynchronously.
  if fd notin p.fdStates: return -1
  var state = addr p.fdStates[fd]
  if state.hasData and state.readLen > 0:
    let n = if state.readLen < bufLen: state.readLen else: bufLen
    copyMem(buf, addr state.readBuf[0], n)
    state.hasData = false
    state.readLen = 0
    state.readPosted = false
    # Re-post the next read
    postRecv(p, fd)
    return n
  result = -1

# ── Polling ──────────────────────────────────────────────────────────────────

proc poll*(p: Platform, timeoutMs: int): int =
  ## Poll for I/O events via IOCP.
  ## Returns completed operations as PlatformEvent entries.
  var numRemoved: DWORD = 0
  type CqEntry = object
    dwNumberOfBytesTransferred: DWORD
    lpCompletionKey: ULONG_PTR
    lpOverlapped: pointer

  const CqBufSize = 256
  var cqBuf: array[CqBufSize, CqEntry]

  let ok = getQueuedCompletionStatusEx(
    p.iocp, addr cqBuf[0], CqBufSize.DWORD,
    numRemoved, timeoutMs.DWORD, 0)

  if not ok or numRemoved == 0:
    p.count = 0
    return 0

  p.count = 0
  for i in 0 ..< numRemoved.int:
    let ext = cast[OverlappedExtPtr](cqBuf[i].lpOverlapped)
    if ext == nil: continue
    case ext.kind
    of opRead:
      if ext.fd in p.fdStates:
        var state = addr p.fdStates[ext.fd]
        state.readLen = cqBuf[i].dwNumberOfBytesTransferred.int
        # Edge case: zero-byte read means peer closed connection
        if state.readLen == 0:
          p.events[p.count] = PlatformEvent(
            fd: ext.fd,
            events: {Read, Hup},
            udata: state.udata
          )
        else:
          state.hasData = true
          p.events[p.count] = PlatformEvent(
            fd: ext.fd,
            events: {Read},
            udata: state.udata
          )
        inc p.count
    of opWrite:
      if ext.fd in p.fdStates:
        p.events[p.count] = PlatformEvent(
          fd: ext.fd,
          events: {Write},
          udata: cast[ptr OverlappedExt](ext).udata
        )
        inc p.count
    of opShutdown:
      # Shutdown/wake event — the loop should break
      p.count = 0
      return 0

  result = p.count

# ── Wake support ─────────────────────────────────────────────────────────────

proc wake*(p: Platform) =
  ## Wake the event loop from another thread.
  discard postQueuedCompletionStatus(p.iocp, 0, 0, nil)
