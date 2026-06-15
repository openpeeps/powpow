# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/platform/epoll.nim — epoll backend for Linux.
##
## Uses Nim's std/epoll for high-performance I/O event multiplexing
## with support for edge-triggered mode and a self-pipe wake mechanism
## for cross-thread loop interruption.

import ../types
import std/[epoll, posix]

const EP_MAX_EVENTS = 1024

# ── Public types ─────────────────────────────────────────────────────────────

type
  PlatformEvent* = object
    fd*:     int
    events*: set[EventType]
    udata*:  pointer

  Platform* = ref object
    epFd:       cint
    epEvents:   seq[EpollEvent]
    events*:    seq[PlatformEvent]
    count*:     int
    wakeReadFd: cint
    wakeWriteFd: cint

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc init*(T: typedesc[Platform]): T =
  result = T()
  result.epFd = epoll_create1(0)
  if result.epFd < 0:
    raise newException(OSError, "powpow: epoll_create1() failed")
  result.epEvents = newSeq[EpollEvent](EP_MAX_EVENTS)
  result.events   = newSeq[PlatformEvent](EP_MAX_EVENTS)
  result.count    = 0

  var pipeFds: array[2, cint]
  if posix.pipe(pipeFds) < 0:
    raise newException(OSError, "powpow: pipe() failed for wake mechanism")
  result.wakeReadFd = pipeFds[0]
  result.wakeWriteFd = pipeFds[1]
  let flags = fcntl(result.wakeReadFd, F_GETFL, 0)
  if flags >= 0: discard fcntl(result.wakeReadFd, F_SETFL, flags or O_NONBLOCK)
  let wflags = fcntl(result.wakeWriteFd, F_GETFL, 0)
  if wflags >= 0: discard fcntl(result.wakeWriteFd, F_SETFL, wflags or O_NONBLOCK)

  var wev: EpollEvent
  wev.events = EPOLLIN
  wev.data.fd = result.wakeReadFd
  if epoll_ctl(result.epFd, EPOLL_CTL_ADD, result.wakeReadFd, addr wev) < 0:
    discard posix.close(result.wakeReadFd)
    discard posix.close(result.wakeWriteFd)
    raise newException(OSError, "powpow: epoll_ctl ADD failed for wake fd")

proc close*(p: Platform) =
  if p.wakeReadFd >= 0:
    discard posix.close(p.wakeReadFd)
    p.wakeReadFd = -1
  if p.wakeWriteFd >= 0:
    discard posix.close(p.wakeWriteFd)
    p.wakeWriteFd = -1
  if p.epFd >= 0:
    discard posix.close(p.epFd)
    p.epFd = -1

# ── Registration ─────────────────────────────────────────────────────────────

proc add*(p: Platform, fd: int, events: set[EventType],
          edgeTriggered = false, udata: pointer = nil) =
  var ev: EpollEvent
  ev.events = 0
  if Read in events:  ev.events = ev.events or EPOLLIN
  if Write in events: ev.events = ev.events or EPOLLOUT
  if edgeTriggered:   ev.events = ev.events or EPOLLET
  let packed = (cast[uint64](udata) shl 32) or cast[uint64](cast[uint32](fd))
  cast[ptr uint64](addr ev.data)[] = packed

  if epoll_ctl(p.epFd, EPOLL_CTL_ADD, fd.cint, addr ev) < 0:
    raise newException(OSError,
      "powpow: epoll_ctl ADD failed for fd " & $fd)

proc remove*(p: Platform, fd: int) =
  var ev: EpollEvent
  discard epoll_ctl(p.epFd, EPOLL_CTL_DEL, fd.cint, addr ev)

proc modify*(p: Platform, fd: int, events: set[EventType],
             edgeTriggered = false, udata: pointer = nil) =
  var ev: EpollEvent
  ev.events = 0
  if Read in events:  ev.events = ev.events or EPOLLIN
  if Write in events: ev.events = ev.events or EPOLLOUT
  if edgeTriggered:   ev.events = ev.events or EPOLLET
  cast[ptr pointer](addr ev.data)[] = udata

  if epoll_ctl(p.epFd, EPOLL_CTL_MOD, fd.cint, addr ev) < 0:
    raise newException(OSError,
      "powpow: epoll_ctl MOD failed for fd " & $fd)

# ── Wake ─────────────────────────────────────────────────────────────────────

proc wake*(p: Platform) =
  var byte: byte = 0
  discard posix.write(p.wakeWriteFd, addr byte, 1)

# ── Polling ──────────────────────────────────────────────────────────────────

proc poll*(p: Platform, timeoutMs: int): int {.inline.} =
  var n: cint
  while true:
    n = epoll_wait(p.epFd, addr p.epEvents[0],
                  EP_MAX_EVENTS.cint, timeoutMs.cint)
    if n < 0:
      if errno == EINTR:
        continue
      p.count = 0
      return 0
    if n == 0:
      p.count = 0
      return 0
    break

  p.count = 0
  for i in 0 ..< n.int:
    let epev = p.epEvents[i]
    if epev.data.fd.int == p.wakeReadFd:
      var buf: array[8, byte]
      discard posix.read(p.wakeReadFd, addr buf[0], 8)
      continue

    let packed = cast[ptr uint64](addr epev.data)[]
    p.events[p.count].fd    = int(packed and 0xFFFF_FFFF'u64)
    p.events[p.count].udata = cast[pointer](packed shr 32)
    p.events[p.count].events = {}

    if (epev.events and EPOLLIN) != 0:   p.events[p.count].events.incl Read
    if (epev.events and EPOLLOUT) != 0:  p.events[p.count].events.incl Write
    if (epev.events and EPOLLERR) != 0:  p.events[p.count].events.incl Error
    if (epev.events and EPOLLHUP) != 0:  p.events[p.count].events.incl Hup

    inc p.count

  return p.count
