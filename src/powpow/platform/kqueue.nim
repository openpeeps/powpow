## powpow/platform/kqueue.nim — kqueue backend for macOS / BSD.
##
## Uses Nim's std/kqueue for high-performance I/O event multiplexing.

import ../types
import std/[kqueue, posix]

const KQ_MAX_EVENTS = 1024

# ── Public types ─────────────────────────────────────────────────────────────

type
  PlatformEvent* = object
    ## A processed I/O event from the kqueue backend.
    fd*:     int
    events*: set[EventType]

  Platform* = ref object
    ## kqueue-based I/O multiplexer with pre-allocated event buffers.
    kqFd:    cint
    kEvents: seq[KEvent]          ## raw kevent buffer
    events*: seq[PlatformEvent]   ## converted events — access via [0..<count]
    count*:  int                  ## number of events from last poll

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc init*(T: typedesc[Platform]): T =
  ## Create a new kqueue platform backend.
  result = T()
  result.kqFd = kqueue()
  if result.kqFd < 0:
    raise newException(OSError, "powpow: kqueue() failed")
  result.kEvents = newSeq[KEvent](KQ_MAX_EVENTS)
  result.events  = newSeq[PlatformEvent](KQ_MAX_EVENTS)
  result.count   = 0

proc close*(p: Platform) =
  ## Close the kqueue fd and release resources.
  if p.kqFd >= 0:
    discard posix.close(p.kqFd)
    p.kqFd = -1

# ── Registration ─────────────────────────────────────────────────────────────

proc add*(p: Platform, fd: int, events: set[EventType],
          edgeTriggered = false) =
  ## Register interest in `events` on `fd`.
  ## `edgeTriggered` uses EV_CLEAR for edge-triggered notification.
  var n = 0
  var changes: array[2, KEvent]
  let flags: cushort =
    if edgeTriggered: EV_ADD or EV_CLEAR
    else:             EV_ADD

  if Read in events:
    changes[n].ident  = fd.csize_t
    changes[n].filter = EVFILT_READ
    changes[n].flags  = flags
    changes[n].fflags = 0
    changes[n].data   = 0
    changes[n].udata  = nil
    inc n
  if Write in events:
    changes[n].ident  = fd.csize_t
    changes[n].filter = EVFILT_WRITE
    changes[n].flags  = flags
    changes[n].fflags = 0
    changes[n].data   = 0
    changes[n].udata  = nil
    inc n

  if n > 0:
    let ret = kevent(p.kqFd, addr changes[0], n.cint, nil, 0, nil)
    if ret < 0:
      raise newException(OSError,
        "powpow: kevent ADD failed for fd " & $fd)

proc remove*(p: Platform, fd: int) =
  ## Remove all event registrations for `fd`.
  # Best-effort: try both filters, ignore errors if not registered.
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
             edgeTriggered = false) =
  ## Change the event interests for an already-registered `fd`.
  p.remove(fd)
  p.add(fd, events, edgeTriggered)

# ── Polling ──────────────────────────────────────────────────────────────────

proc poll*(p: Platform, timeoutMs: int): int {.inline.} =
  ## Poll for I/O events.
  ##
  ## - `timeoutMs = -1` — block until an event fires
  ## - `timeoutMs = 0`  — return immediately (non-blocking)
  ## - `timeoutMs > 0`  — wait up to N milliseconds
  ##
  ## Returns the number of events. Access them via `p.events[0..<p.count]`.
  var ts: Timespec
  var tsPtr: ptr Timespec = nil

  if timeoutMs >= 0:
    ts.tv_sec  = Time(timeoutMs div 1000)
    ts.tv_nsec = (timeoutMs mod 1000) * 1_000_000
    tsPtr = addr ts

  var n: cint
  while true:
    n = kevent(p.kqFd, nil, 0,
               addr p.kEvents[0], KQ_MAX_EVENTS.cint, tsPtr)
    if n < 0:
      if errno == EINTR:
        continue  # interrupted by signal — retry
      p.count = 0
      return 0
    if n == 0:
      p.count = 0
      return 0  # timeout
    break

  p.count = n.int
  for i in 0 ..< n.int:
    let kev = p.kEvents[i]
    p.events[i].fd     = kev.ident.int
    p.events[i].events = {}

    if (kev.flags and EV_ERROR) != 0:
      p.events[i].events.incl Error
    if (kev.flags and EV_EOF) != 0:
      p.events[i].events.incl Hup
    if kev.filter == EVFILT_READ and (kev.flags and EV_ERROR) == 0:
      p.events[i].events.incl Read
    elif kev.filter == EVFILT_WRITE and (kev.flags and EV_ERROR) == 0:
      p.events[i].events.incl Write

  return p.count
