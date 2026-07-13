# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/platform/epoll.nim — epoll backend for Linux.
##
## Uses Nim's std/epoll for high-performance I/O event multiplexing
## with support for edge-triggered mode and an eventfd wake mechanism
## for cross-thread loop interruption.

import ../types
import std/[epoll, posix]

const
  EventCapacityMin = 64
  EventCapacityMax = 16384

# ── eventfd ──────────────────────────────────────────────────────────────────

proc eventfd(initval: cuint, flags: cint): cint {.
  importc: "eventfd", header: "<sys/eventfd.h>".}

const EFD_NONBLOCK = 0x800

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
    wakeFd:     cint

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc init*(T: typedesc[Platform]): T =
  result = T()
  result.epFd = epoll_create1(0)
  if result.epFd < 0:
    raise newException(OSError, "powpow: epoll_create1() failed")
  result.epEvents = newSeq[EpollEvent](EventCapacityMin)
  result.events   = newSeq[PlatformEvent](EventCapacityMin)
  result.count    = 0

  result.wakeFd = eventfd(0, EFD_NONBLOCK)
  if result.wakeFd < 0:
    raise newException(OSError, "powpow: eventfd() failed for wake mechanism")

  var wev: EpollEvent
  wev.events = EPOLLIN
  wev.data.fd = result.wakeFd
  if epoll_ctl(result.epFd, EPOLL_CTL_ADD, result.wakeFd, addr wev) < 0:
    discard posix.close(result.wakeFd)
    raise newException(OSError, "powpow: epoll_ctl ADD failed for wake fd")

proc close*(p: Platform) =
  if p.wakeFd >= 0:
    discard posix.close(p.wakeFd)
    p.wakeFd = -1
  if p.epFd >= 0:
    discard posix.close(p.epFd)
    p.epFd = -1

# ── Capacity ─────────────────────────────────────────────────────────────────

proc ensureCapacity*(p: Platform, fdCount: int) {.inline.} =
  let target = min(max(fdCount * 2, EventCapacityMin), EventCapacityMax)
  if target > p.events.len:
    p.events.setLen(target)
    p.epEvents.setLen(target)

# ── Registration ─────────────────────────────────────────────────────────────

proc add*(p: Platform, fd: int, events: set[EventType],
          edgeTriggered = false, udata: pointer = nil) =
  var ev: EpollEvent
  ev.events = 0
  if Read in events:  ev.events = ev.events or EPOLLIN
  if Write in events: ev.events = ev.events or EPOLLOUT
  ev.data.ptr = udata

  let ret = epoll_ctl(p.epFd, EPOLL_CTL_ADD, fd.cint, addr ev)
  if ret < 0:
    if errno == EEXIST:
      if epoll_ctl(p.epFd, EPOLL_CTL_MOD, fd.cint, addr ev) < 0:
        raise newException(OSError,
          "powpow: epoll_ctl MOD failed for fd " & $fd)
    else:
      raise newException(OSError,
        "powpow: epoll_ctl ADD failed for fd " & $fd)

proc remove*(p: Platform, fd: int) {.inline.} =
  var ev: EpollEvent
  discard epoll_ctl(p.epFd, EPOLL_CTL_DEL, fd.cint, addr ev)

proc modify*(p: Platform, fd: int, events: set[EventType],
             edgeTriggered = false, udata: pointer = nil) =
  var ev: EpollEvent
  ev.events = 0
  if Read in events:  ev.events = ev.events or EPOLLIN
  if Write in events: ev.events = ev.events or EPOLLOUT
  ev.data.ptr = udata

  if epoll_ctl(p.epFd, EPOLL_CTL_MOD, fd.cint, addr ev) < 0:
    raise newException(OSError,
      "powpow: epoll_ctl MOD failed for fd " & $fd)

# ── Wake ─────────────────────────────────────────────────────────────────────

proc wake*(p: Platform) {.inline.} =
  var val: uint64 = 1
  discard posix.write(p.wakeFd, addr val, 8)

# ── Polling ──────────────────────────────────────────────────────────────────

proc poll*(p: Platform, timeoutMs: int): int {.inline.} =
  var n: cint
  while true:
    n = epoll_wait(p.epFd, addr p.epEvents[0],
                   p.epEvents.len.cint, timeoutMs.cint)
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
    if epev.data.fd.int == p.wakeFd:
      var val: uint64
      discard posix.read(p.wakeFd, addr val, 8)
      continue

    p.events[p.count].fd     = epev.data.fd.int
    p.events[p.count].udata  = epev.data.ptr
    p.events[p.count].events = {}

    if (epev.events and EPOLLIN) != 0:   p.events[p.count].events.incl Read
    if (epev.events and EPOLLOUT) != 0:  p.events[p.count].events.incl Write
    if (epev.events and EPOLLERR) != 0:  p.events[p.count].events.incl Error
    if (epev.events and EPOLLHUP) != 0:  p.events[p.count].events.incl Hup

    inc p.count

  return p.count
