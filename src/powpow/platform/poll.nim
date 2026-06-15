## powpow/platform/poll.nim — poll(2) fallback backend.
##
## Universal I/O multiplexing via poll(2). Used when neither kqueue nor
## epoll is available. Does NOT support edge-triggered mode.

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
    ## A processed I/O event from the poll backend.
    fd*:     int
    events*: set[EventType]

  Platform* = ref object
    ## poll(2)-based I/O multiplexer.
    pollFds:   seq[Pollfd]
    fdToIdx:   Table[int, int]       ## fd → index in pollFds
    events*:   seq[PlatformEvent]    ## converted events
    count*:    int                   ## number of events from last poll

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc init*(T: typedesc[Platform]): T =
  ## Create a new poll-based platform backend.
  result = T()
  result.pollFds = newSeq[Pollfd]()
  result.fdToIdx = initTable[int, int](64)
  result.events  = newSeq[PlatformEvent](POLL_MAX_EVENTS)
  result.count   = 0

proc close*(p: Platform) =
  ## Release resources.
  p.pollFds.setLen(0)
  p.fdToIdx.clear()

# ── Registration ─────────────────────────────────────────────────────────────

proc add*(p: Platform, fd: int, events: set[EventType],
          edgeTriggered = false) =
  ## Register interest in `events` on `fd`.
  ## Note: `edgeTriggered` is ignored — poll(2) is always level-triggered.
  var pfd: Pollfd
  pfd.fd      = fd.cint
  pfd.events  = 0
  pfd.revents = 0
  if Read in events:  pfd.events = pfd.events or POLLIN
  if Write in events: pfd.events = pfd.events or POLLOUT

  let idx = p.pollFds.len
  p.pollFds.add(pfd)
  p.fdToIdx[fd] = idx

proc remove*(p: Platform, fd: int) =
  ## Remove all event registrations for `fd`.
  if fd notin p.fdToIdx: return
  let idx   = p.fdToIdx[fd]
  let last  = p.pollFds.len - 1

  # Swap-remove for O(1) deletion
  if idx != last:
    p.pollFds[idx] = p.pollFds[last]
    p.fdToIdx[p.pollFds[idx].fd.int] = idx

  p.pollFds.setLen(p.pollFds.len - 1)
  p.fdToIdx.del(fd)

proc modify*(p: Platform, fd: int, events: set[EventType],
             edgeTriggered = false) =
  ## Change the event interests for an already-registered `fd`.
  if fd notin p.fdToIdx: return
  let idx = p.fdToIdx[fd]
  p.pollFds[idx].events = 0
  if Read in events:  p.pollFds[idx].events = p.pollFds[idx].events or POLLIN
  if Write in events: p.pollFds[idx].events = p.pollFds[idx].events or POLLOUT

# ── Polling ──────────────────────────────────────────────────────────────────

proc poll*(p: Platform, timeoutMs: int): int {.inline.} =
  ## Poll for I/O events. See kqueue/epoll backends for timeout semantics.
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

    var evts: set[EventType] = {}
    if (rev and POLLIN) != 0:   evts.incl Read
    if (rev and POLLOUT) != 0:  evts.incl Write
    if (rev and POLLERR) != 0:  evts.incl Error
    if (rev and POLLHUP) != 0:  evts.incl Hup

    p.events[p.count] = PlatformEvent(
      fd:     p.pollFds[i].fd.int,
      events: evts
    )
    inc p.count

  return p.count
