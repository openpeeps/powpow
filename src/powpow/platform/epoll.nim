# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## This module implements the `Platform` interface using Linux's `epoll` API.
## It provides efficient I/O event notification for file descriptors, supporting
## both level-triggered and edge-triggered modes. The `Platform` type manages an epoll instance and
## pre-allocated event buffers for high performance.

import ../types
import std/[epoll, posix]

const EP_MAX_EVENTS = 1024

# ── Public types ─────────────────────────────────────────────────────────────

type
  PlatformEvent* = object
    ## A processed I/O event from the epoll backend.
    fd*:     int
    events*: set[EventType]
    udata*:  pointer          ## Opaque user data from registration

  Platform* = ref object
    ## epoll-based I/O multiplexer with pre-allocated event buffers.
    epFd:     cint
    epEvents: seq[EpollEvent]        ## raw epoll_event buffer
    events*:  seq[PlatformEvent]     ## converted events — access via [0..<count]
    count*:   int                    ## number of events from last poll

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc init*(T: typedesc[Platform]): T =
  ## Create a new epoll platform backend.
  result = T()
  result.epFd = epoll_create1(0)
  if result.epFd < 0:
    raise newException(OSError, "powpow: epoll_create1() failed")
  result.epEvents = newSeq[EpollEvent](EP_MAX_EVENTS)
  result.events   = newSeq[PlatformEvent](EP_MAX_EVENTS)
  result.count    = 0

proc close*(p: Platform) =
  ## Close the epoll fd and release resources.
  if p.epFd >= 0:
    discard posix.close(p.epFd)
    p.epFd = -1

# ── Registration ─────────────────────────────────────────────────────────────

proc add*(p: Platform, fd: int, events: set[EventType],
          edgeTriggered = false, udata: pointer = nil) =
  ## Register interest in `events` on `fd`.
  ## `edgeTriggered` uses EPOLLET for edge-triggered notification.
  ## `udata` is opaque user data returned in `PlatformEvent.udata` on poll.
  var ev: EpollEvent
  ev.events = 0
  if Read in events:  ev.events = ev.events or EPOLLIN
  if Write in events: ev.events = ev.events or EPOLLOUT
  if edgeTriggered:   ev.events = ev.events or EPOLLET
  # cast[ptr pointer](addr ev.data)[] = udata
  let packed = (cast[uint64](udata) shl 32) or cast[uint64](cast[uint32](fd))
  cast[ptr uint64](addr ev.data)[] = packed

  if epoll_ctl(p.epFd, EPOLL_CTL_ADD, fd.cint, addr ev) < 0:
    raise newException(OSError,
      "powpow: epoll_ctl ADD failed for fd " & $fd)

proc remove*(p: Platform, fd: int) =
  ## Remove all event registrations for `fd`.
  var ev: EpollEvent  # ignored by kernel for DEL
  discard epoll_ctl(p.epFd, EPOLL_CTL_DEL, fd.cint, addr ev)

proc modify*(p: Platform, fd: int, events: set[EventType],
             edgeTriggered = false, udata: pointer = nil) =
  ## Change the event interests for an already-registered `fd`.
  var ev: EpollEvent
  ev.events = 0
  if Read in events:  ev.events = ev.events or EPOLLIN
  if Write in events: ev.events = ev.events or EPOLLOUT
  if edgeTriggered:   ev.events = ev.events or EPOLLET
  cast[ptr pointer](addr ev.data)[] = udata

  if epoll_ctl(p.epFd, EPOLL_CTL_MOD, fd.cint, addr ev) < 0:
    raise newException(OSError,
      "powpow: epoll_ctl MOD failed for fd " & $fd)

# ── Polling ──────────────────────────────────────────────────────────────────

proc poll*(p: Platform, timeoutMs: int): int {.inline.} =
  ## Poll for I/O events.
  ##
  ## - `timeoutMs = -1` — block until an event fires
  ## - `timeoutMs = 0`  — return immediately (non-blocking)
  ## - `timeoutMs > 0`  — wait up to N milliseconds
  ##
  ## Returns the number of events. Access via `p.events[0..<p.count]`.
  var n: cint
  while true:
    n = epoll_wait(p.epFd, addr p.epEvents[0],
                  EP_MAX_EVENTS.cint, timeoutMs.cint)
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
    let epev = p.epEvents[i]
    let packed = cast[ptr uint64](addr epev.data)[]
    p.events[i].fd    = int(packed and 0xFFFF_FFFF'u64)
    p.events[i].udata = cast[pointer](packed shr 32)

    if (epev.events and EPOLLIN) != 0:   p.events[i].events.incl Read
    if (epev.events and EPOLLOUT) != 0:  p.events[i].events.incl Write
    if (epev.events and EPOLLERR) != 0:  p.events[i].events.incl Error
    if (epev.events and EPOLLHUP) != 0:  p.events[i].events.incl Hup

  return p.count
