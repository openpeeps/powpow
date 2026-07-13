# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/platform/kqueue.nim — kqueue backend for macOS / BSD.
##
## Uses Nim's std/kqueue for high-performance I/O event multiplexing
## with a pipe-based wake mechanism for cross-thread loop interruption.

import ../types
import std/[kqueue, posix]

const
  EventCapacityMin = 64
  EventCapacityMax = 16384

# ── Public types ─────────────────────────────────────────────────────────────

type
  PlatformEvent* = object
    fd*:     int
    events*: set[EventType]
    udata*:  pointer

  Platform* = ref object
    kqFd:       cint
    kEvents:    seq[KEvent]
    events*:    seq[PlatformEvent]
    count*:     int
    wakeReadFd: cint
    wakeWriteFd: cint

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc init*(T: typedesc[Platform]): T =
  result = T()
  result.kqFd = kqueue()
  if result.kqFd < 0:
    raise newException(OSError, "powpow: kqueue() failed")
  result.kEvents = newSeq[KEvent](EventCapacityMin)
  result.events  = newSeq[PlatformEvent](EventCapacityMin)
  result.count   = 0

  var pipeFds: array[2, cint]
  if posix.pipe(pipeFds) < 0:
    raise newException(OSError, "powpow: pipe() failed for wake mechanism")
  result.wakeReadFd = pipeFds[0]
  result.wakeWriteFd = pipeFds[1]
  let flags = fcntl(result.wakeReadFd, F_GETFL, 0)
  if flags >= 0: discard fcntl(result.wakeReadFd, F_SETFL, flags or O_NONBLOCK)
  let wflags = fcntl(result.wakeWriteFd, F_GETFL, 0)
  if wflags >= 0: discard fcntl(result.wakeWriteFd, F_SETFL, wflags or O_NONBLOCK)

  var wev: KEvent
  wev.ident  = result.wakeReadFd.csize_t
  wev.filter = EVFILT_READ
  wev.flags  = EV_ADD or EV_CLEAR
  wev.fflags = 0
  wev.data   = 0
  wev.udata  = nil
  if kevent(result.kqFd, addr wev, 1, nil, 0, nil) < 0:
    discard posix.close(result.wakeReadFd)
    discard posix.close(result.wakeWriteFd)
    raise newException(OSError, "powpow: kevent ADD failed for wake fd")

proc close*(p: Platform) =
  if p.wakeReadFd >= 0:
    discard posix.close(p.wakeReadFd)
    p.wakeReadFd = -1
  if p.wakeWriteFd >= 0:
    discard posix.close(p.wakeWriteFd)
    p.wakeWriteFd = -1
  if p.kqFd >= 0:
    discard posix.close(p.kqFd)
    p.kqFd = -1

# ── Capacity ─────────────────────────────────────────────────────────────────

proc ensureCapacity*(p: Platform, fdCount: int) {.inline.} =
  let target = min(max(fdCount * 2, EventCapacityMin), EventCapacityMax)
  if target > p.events.len:
    p.events.setLen(target)
    p.kEvents.setLen(target)

# ── Registration ─────────────────────────────────────────────────────────────

proc add*(p: Platform, fd: int, events: set[EventType],
          edgeTriggered = false, udata: pointer = nil) =
  var n = 0
  var changes: array[2, KEvent]
  let readFlags: cushort =
    if edgeTriggered: EV_ADD or EV_CLEAR
    else:             EV_ADD

  if Read in events:
    changes[n].ident  = fd.csize_t
    changes[n].filter = EVFILT_READ
    changes[n].flags  = readFlags
    changes[n].fflags = 0
    changes[n].data   = 0
    changes[n].udata  = udata
    inc n
  if Write in events:
    changes[n].ident  = fd.csize_t
    changes[n].filter = EVFILT_WRITE
    changes[n].flags  = EV_ADD
    changes[n].fflags = 0
    changes[n].data   = 0
    changes[n].udata  = udata
    inc n

  if n > 0:
    let ret = kevent(p.kqFd, addr changes[0], n.cint, nil, 0, nil)
    if ret < 0:
      raise newException(OSError,
        "powpow: kevent ADD failed for fd " & $fd)

proc remove*(p: Platform, fd: int) =
  var rd: KEvent
  rd.ident  = fd.csize_t
  rd.filter = EVFILT_READ
  rd.flags  = EV_DELETE
  rd.fflags = 0
  rd.data   = 0
  rd.udata  = nil

  var wr: KEvent
  wr.ident  = fd.csize_t
  wr.filter = EVFILT_WRITE
  wr.flags  = EV_DELETE
  wr.fflags = 0
  wr.data   = 0
  wr.udata  = nil

  discard kevent(p.kqFd, addr rd, 1, nil, 0, nil)
  discard kevent(p.kqFd, addr wr, 1, nil, 0, nil)

proc modify*(p: Platform, fd: int, events: set[EventType],
             edgeTriggered = false, udata: pointer = nil) =
  var n = 0
  var changes: array[2, KEvent]
  let readFlags: cushort =
    if edgeTriggered: EV_ADD or EV_CLEAR
    else:             EV_ADD

  changes[n].ident  = fd.csize_t
  changes[n].filter = EVFILT_READ
  changes[n].fflags = 0
  changes[n].data   = 0
  changes[n].udata  = udata
  if Read in events:
    changes[n].flags = readFlags
  else:
    changes[n].flags = EV_DELETE
  inc n

  changes[n].ident  = fd.csize_t
  changes[n].filter = EVFILT_WRITE
  changes[n].fflags = 0
  changes[n].data   = 0
  changes[n].udata  = udata
  if Write in events:
    changes[n].flags = EV_ADD
  else:
    changes[n].flags = EV_DELETE
  inc n

  discard kevent(p.kqFd, addr changes[0], n.cint, nil, 0, nil)

# ── Wake ─────────────────────────────────────────────────────────────────────

proc wake*(p: Platform) {.inline.} =
  var byte: byte = 0
  discard posix.write(p.wakeWriteFd, addr byte, 1)

# ── Polling ──────────────────────────────────────────────────────────────────

proc poll*(p: Platform, timeoutMs: int): int {.inline.} =
  var ts: Timespec
  var tsPtr: ptr Timespec = nil

  if timeoutMs >= 0:
    ts.tv_sec  = Time(timeoutMs div 1000)
    ts.tv_nsec = (timeoutMs mod 1000) * 1_000_000
    tsPtr = addr ts

  var n: cint
  while true:
    n = kevent(p.kqFd, nil, 0,
               addr p.kEvents[0], p.kEvents.len.cint, tsPtr)
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
    let kev = p.kEvents[i]
    if kev.ident.int == p.wakeReadFd:
      var buf: array[8, byte]
      discard posix.read(p.wakeReadFd, addr buf[0], 8)
      continue

    p.events[p.count].fd     = kev.ident.int
    p.events[p.count].events = {}
    p.events[p.count].udata  = kev.udata

    if (kev.flags and EV_ERROR) != 0:
      p.events[p.count].events.incl Error
    if (kev.flags and EV_EOF) != 0:
      p.events[p.count].events.incl Hup
    if kev.filter == EVFILT_READ and (kev.flags and EV_ERROR) == 0:
      p.events[p.count].events.incl Read
    elif kev.filter == EVFILT_WRITE and (kev.flags and EV_ERROR) == 0:
      p.events[p.count].events.incl Write

    inc p.count

  return p.count
