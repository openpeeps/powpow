# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/platform/poll.nim — poll(2) fallback backend.
##
## Universal I/O multiplexing via poll(2). Used when neither kqueue nor
## epoll is available. Does NOT support edge-triggered mode.
## Includes a pipe-based wake mechanism for cross-thread loop interruption.

import ../types
import std/tables

# ── poll constants ───────────────────────────────────────────────────────────

const
  POLLIN   = 0x001.cshort
  POLLOUT  = 0x004.cshort
  POLLERR  = 0x008.cshort
  POLLHUP  = 0x010.cshort
  POLLNVAL = 0x020.cshort

const POLL_MAX_EVENTS = 1024

# ── C struct / syscall bindings ──────────────────────────────────────────────

type
  Pollfd {.importc: "struct pollfd", header: "<poll.h>",
           pure, final.} = object
    fd:      cint
    events:  cshort
    revents: cshort

proc c_poll(fds: ptr Pollfd, nfds: cuint,
            timeout: cint): cint {.importc: "poll", header: "<poll.h>".}

# ── Public types ─────────────────────────────────────────────────────────────

type
  PlatformEvent* = object
    fd*:     int
    events*: set[EventType]
    udata*:  pointer

  Platform* = ref object
    pollFds:    seq[Pollfd]
    fdToIdx:    Table[int, int]
    udataMap:   Table[int, pointer]
    events*:    seq[PlatformEvent]
    count*:     int
    wakeReadFd: cint
    wakeWriteFd: cint

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc init*(T: typedesc[Platform]): T =
  result = T()
  result.pollFds = newSeq[Pollfd]()
  result.fdToIdx = initTable[int, int](64)
  result.udataMap = initTable[int, pointer](64)
  result.events  = newSeq[PlatformEvent](POLL_MAX_EVENTS)
  result.count   = 0

  var pipeFds: array[2, cint]
  if c_pipe(addr pipeFds[0]) < 0:
    raise newException(OSError, "powpow: pipe() failed for wake mechanism")
  result.wakeReadFd = pipeFds[0]
  result.wakeWriteFd = pipeFds[1]
  let flags = fcntl(result.wakeReadFd, F_GETFL, 0)
  if flags >= 0: discard fcntl(result.wakeReadFd, F_SETFL, flags or O_NONBLOCK)
  let wflags = fcntl(result.wakeWriteFd, F_GETFL, 0)
  if wflags >= 0: discard fcntl(result.wakeWriteFd, F_SETFL, wflags or O_NONBLOCK)

  var pfd: Pollfd
  pfd.fd = result.wakeReadFd
  pfd.events = POLLIN
  pfd.revents = 0
  result.pollFds.add(pfd)

proc close*(p: Platform) =
  if p.wakeReadFd >= 0:
    discard c_close(p.wakeReadFd)
    p.wakeReadFd = -1
  if p.wakeWriteFd >= 0:
    discard c_close(p.wakeWriteFd)
    p.wakeWriteFd = -1
  p.pollFds.setLen(0)
  p.fdToIdx.clear()

# ── C wrappers ───────────────────────────────────────────────────────────────

proc c_pipe(fds: ptr cint): cint {.importc: "pipe", header: "<unistd.h>".}
proc c_close(fd: cint): cint {.importc: "close", header: "<unistd.h>".}
proc fcntl(fd: cint, cmd: cint, arg: cint): cint {.
  importc: "fcntl", header: "<fcntl.h>".}
proc write(fd: cint, buf: pointer, count: csize_t): cint {.
  importc: "write", header: "<unistd.h>".}
proc read(fd: cint, buf: pointer, count: csize_t): cint {.
  importc: "read", header: "<unistd.h>".}

const
  F_GETFL = 3
  F_SETFL = 4
  O_NONBLOCK = 4

# ── Registration ─────────────────────────────────────────────────────────────

proc add*(p: Platform, fd: int, events: set[EventType],
          edgeTriggered = false, udata: pointer = nil) =
  var pfd: Pollfd
  pfd.fd      = fd.cint
  pfd.events  = 0
  pfd.revents = 0
  if Read in events:  pfd.events = pfd.events or POLLIN
  if Write in events: pfd.events = pfd.events or POLLOUT

  let idx = p.pollFds.len
  p.pollFds.add(pfd)
  p.fdToIdx[fd] = idx
  p.udataMap[fd] = udata

proc remove*(p: Platform, fd: int) =
  if fd == p.wakeReadFd: return
  if fd notin p.fdToIdx: return
  let idx   = p.fdToIdx[fd]
  let last  = p.pollFds.len - 1

  if idx != last:
    p.pollFds[idx] = p.pollFds[last]
    p.fdToIdx[p.pollFds[idx].fd.int] = idx

  p.pollFds.setLen(p.pollFds.len - 1)
  p.fdToIdx.del(fd)
  p.udataMap.del(fd)

proc modify*(p: Platform, fd: int, events: set[EventType],
             edgeTriggered = false, udata: pointer = nil) =
  if fd notin p.fdToIdx: return
  let idx = p.fdToIdx[fd]
  p.pollFds[idx].events = 0
  if Read in events:  p.pollFds[idx].events = p.pollFds[idx].events or POLLIN
  if Write in events: p.pollFds[idx].events = p.pollFds[idx].events or POLLOUT
  p.udataMap[fd] = udata

# ── Wake ─────────────────────────────────────────────────────────────────────

proc wake*(p: Platform) =
  var byte: byte = 0
  discard write(p.wakeWriteFd, addr byte, 1)

# ── Polling ──────────────────────────────────────────────────────────────────

proc poll*(p: Platform, timeoutMs: int): int {.inline.} =
  if p.pollFds.len == 0:
    p.count = 0
    return 0

  let n = c_poll(addr p.pollFds[0],
                 p.pollFds.len.cuint, timeoutMs.cint)
  if n <= 0:
    p.count = 0
    return 0

  p.count = 0
  for i in 0 ..< p.pollFds.len:
    let rev = p.pollFds[i].revents
    if rev == 0: continue

    if p.pollFds[i].fd.int == p.wakeReadFd:
      var buf: array[8, byte]
      discard read(p.wakeReadFd, addr buf[0], 8)
      continue

    var evts: set[EventType] = {}
    if (rev and POLLIN) != 0:   evts.incl Read
    if (rev and POLLOUT) != 0:  evts.incl Write
    if (rev and POLLERR) != 0:  evts.incl Error
    if (rev and POLLHUP) != 0:  evts.incl Hup

    p.events[p.count] = PlatformEvent(
      fd:     p.pollFds[i].fd.int,
      events: evts,
      udata:  p.udataMap.getOrDefault(p.pollFds[i].fd.int, nil),
    )
    inc p.count

  return p.count
