# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/platform/kqueue.nim — kqueue backend for macOS / BSD.
##
## Uses Nim's std/kqueue for high-performance I/O event multiplexing
## with a wake mechanism for cross-thread loop interruption.
##
## Three backend-specific optimisations are layered on top of plain kqueue(2):
##
## 1. **Per-fd filter state.** Every knote's currently-registered filters are
##    tracked in a direct-indexed table, so `add`/`modify`/`remove` emit only
##    the changes that actually differ. The pre-change `remove` spent two
##    separate `kevent()` calls and the second was always a guaranteed-`ENOENT`
##    no-op for an idle connection; `modify` re-`EV_ADD`ed an already-registered
##    read filter on every call.
##
##    `EV_DISABLE`/`EV_ENABLE` (keeping both knotes warm instead of
##    delete/re-add) is deliberately *not* used: it doubles the knote count for
##    idle connections, and `kevent()` cost scales with registered knotes on
##    every call — charging the hot read path to speed up the rare
##    write-backpressure path is a bad trade.
##
## 2. **Staged changelist (macOS).** Registration changes are appended to a
##    reusable changelist and flushed in the *same* `kevent()` call as the
##    blocking wait, so an accept burst costs one syscall instead of one per fd.
##    The invariant is that changes are only ever flushed at the top of `poll()`,
##    never after the wait, so nothing is deferred past a blocking point.
##
## 3. **EVFILT_USER wake.** Where the platform has `EVFILT_USER`, the wake pipe
##    is replaced by a user knote: no fds consumed, and nothing to drain in the
##    poll path. The pipe drain also had a lost-wakeup edge — it read 8 bytes
##    while `wake()` writes 1 byte per call, and `EV_CLEAR` deactivates the
##    knote after the first report, so 9+ piled-up wake bytes left the pipe
##    readable with no edge left to re-fire on.

import ../types
import std/[kqueue, posix, monotimes]

const
  EventCapacityMin = 512
  EventCapacityMax = 16384

const
  ## Stage registration changes in a changelist flushed with the next wait.
  ## macOS only — FreeBSD/NetBSD/OpenBSD keep the immediate `kevent()` path.
  changelistBatched = defined(macosx)
  ## EVFILT_USER replaces the pipe-based wake mechanism where it exists.
  userFilterAvailable =
    defined(macosx) or defined(freebsd) or defined(netbsd) or defined(openbsd)

when userFilterAvailable:
  # Not exported by std/kqueue. Verified against <sys/event.h>:
  #   #define EVFILT_USER  (-10)
  #   #define NOTE_TRIGGER 0x01000000
  const
    EvFilterUser = -10
    NoteTrigger  = 0x01000000.cuint

# ── Per-fd knote state ────────────────────────────────────────────────────────

const
  FiltRead  = 1'u8   ## EVFILT_READ is registered
  FiltWrite = 2'u8   ## EVFILT_WRITE is registered
  FiltClear = 4'u8   ## registered edge-triggered (EV_CLEAR)
  FiltAny    = FiltRead or FiltWrite

type
  FilterSlot = object
    udata: pointer   ## dispatch pointer the kernel currently holds
    mask:  uint8     ## FiltRead/FiltWrite/FiltClear

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
    wakeReadFd: cint         ## pipe wake, or -1 when EVFILT_USER is in use
    wakeWriteFd: cint
    fslots:     seq[FilterSlot]  ## direct-indexed by fd
    scratch:    FilterSlot       ## slot used for out-of-range fds
    pending:    seq[KEvent]      ## staged changelist (macOS)
    pendingFd:  seq[int]         ## fd owning each staged change
    pendErrFd:  int              ## fd of the last rejected change, -1 when none
    pendErrNo:  int

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc raiseFd(fd: var cint) {.inline.} =
  ## Keep the loop's control fds out of the 0..2 range. Nim's runtime does not
  ## open the standard descriptors at startup, so kqueue()/pipe() can land on
  ## fd 0/1/2; those can later be reused by application sockets, silently
  ## clobbering the loop's kqueue/wake. Duplicate to the lowest free fd >= 3
  ## and close the original.
  if fd >= 0 and fd < 3:
    let nf = fcntl(fd, F_DUPFD, 3)
    if nf >= 0:
      discard posix.close(fd)
      fd = nf

proc init*(T: typedesc[Platform]): T =
  result = T()
  result.kqFd = kqueue()
  if result.kqFd < 0:
    raise newException(OSError, "powpow: kqueue() failed")
  result.kqFd.raiseFd()
  result.kEvents = newSeq[KEvent](EventCapacityMin)
  result.events  = newSeq[PlatformEvent](EventCapacityMin)
  result.count   = 0
  result.wakeReadFd = -1
  result.wakeWriteFd = -1
  result.pendErrFd = -1
  result.fslots  = newSeqOfCap[FilterSlot](256)
  result.pending = newSeqOfCap[KEvent](32)
  result.pendingFd = newSeqOfCap[int](32)

  when userFilterAvailable:
    var wev: KEvent
    wev.ident  = 0                      ## ident is ignored for EVFILT_USER
    wev.filter = EvFilterUser.cshort
    wev.flags  = (EV_ADD or EV_CLEAR).cushort
    wev.fflags = 0
    wev.data   = 0
    wev.udata  = nil
    if kevent(result.kqFd, addr wev, 1, nil, 0, nil) < 0:
      discard posix.close(result.kqFd)
      raise newException(OSError, "powpow: kevent ADD failed for EVFILT_USER wake")
  else:
    var pipeFds: array[2, cint]
    if posix.pipe(pipeFds) < 0:
      discard posix.close(result.kqFd)
      raise newException(OSError, "powpow: pipe() failed for wake mechanism")
    result.wakeReadFd = pipeFds[0]
    result.wakeWriteFd = pipeFds[1]
    result.wakeReadFd.raiseFd()
    result.wakeWriteFd.raiseFd()
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
      discard posix.close(result.kqFd)
      raise newException(OSError, "powpow: kevent ADD failed for wake fd")

proc close*(p: Platform) =
  p.pending.setLen(0)
  p.pendingFd.setLen(0)
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

proc slotFor(p: Platform, fd: int): ptr FilterSlot {.inline.} =
  ## Registration state for `fd`, growing the table on demand. fds on POSIX are
  ## recycled from the lowest free number, so the table stays bounded by the
  ## peak concurrent fd count.
  if fd < 0:
    p.scratch = default(FilterSlot)
    return addr p.scratch
  if fd >= p.fslots.len:
    var n = max(p.fslots.len, 256)
    while n <= fd: n *= 2
    p.fslots.setLen(n)
  addr p.fslots[fd]

# ── Registration ─────────────────────────────────────────────────────────────

proc mk(ev: var KEvent, fd: int, filter: int, flags: cushort,
        udata: pointer) {.inline.} =
  ev.ident  = fd.csize_t
  ev.filter = filter.cshort
  ev.flags  = flags
  ev.fflags = 0
  ev.data   = 0
  ev.udata  = udata

proc submit(p: Platform, changes: ptr KEvent, n: int, fd: int) =
  ## Apply `n` changes for `fd`. On macOS they are staged and flushed together
  ## with the next wait; elsewhere they go out immediately.
  when changelistBatched:
    let arr = cast[ptr UncheckedArray[KEvent]](changes)
    for i in 0 ..< n:
      p.pending.add(arr[i])
      p.pendingFd.add(fd)
  else:
    if n > 0:
      if kevent(p.kqFd, changes, n.cint, nil, 0, nil) < 0:
        raise newException(OSError,
          "powpow: kevent change failed for fd " & $fd & ": " & $strerror(errno))

proc add*(p: Platform, fd: int, events: set[EventType],
          edgeTriggered = false, udata: pointer = nil) =
  var want: uint8 = 0
  if Read in events:  want = want or FiltRead
  if Write in events: want = want or FiltWrite
  if edgeTriggered:    want = want or FiltClear

  let slot = p.slotFor(fd)

  # NOTE: `add` always emits its changes, even when the table already describes
  # this fd. The table cannot tell "still registered" from "fd was closed and the
  # number was recycled": POSIX drops the knote on `close()`, and
  # `loop.unregisterFd` deliberately does not call `remove()`, so the stale entry
  # survives. If the recycled fd also gets the same `FdWatcher` pointer back
  # from `fdWatcherPool`, a skip here would leave the new connection with no
  # knote at all and it would hang forever. `add` is the registration entry point
  # and must always reach the kernel; on macOS it is staged into the changelist,
  # so it costs no extra syscall anyway.
  var n = 0
  var changes: array[2, KEvent]
  let addFlags: cushort =
    if edgeTriggered: (EV_ADD or EV_CLEAR).cushort else: EV_ADD.cushort

  if Read in events:
    mk(changes[n], fd, EVFILT_READ, addFlags, udata)
    inc n
  if Write in events:
    mk(changes[n], fd, EVFILT_WRITE, addFlags, udata)
    inc n

  slot.mask = want
  if n > 0:
    slot.udata = udata
  p.submit(addr changes[0], n, fd)

proc remove*(p: Platform, fd: int) =
  var n = 0
  var changes: array[2, KEvent]

  let slot = p.slotFor(fd)
  let have = slot.mask and FiltAny
  if (have and FiltRead) != 0:
    mk(changes[n], fd, EVFILT_READ, EV_DELETE.cushort, nil)
    inc n
  if (have and FiltWrite) != 0:
    mk(changes[n], fd, EVFILT_WRITE, EV_DELETE.cushort, nil)
    inc n
  if n == 0:
    # Nothing tracked for this fd (never registered through `add`, or its state
    # was already cleared). Blind-delete both filters in a single `kevent()`
    # rather than leak a knote if the bookkeeping is ever wrong; this is the
    # defensive path and does not run for a normally-registered fd.
    mk(changes[n], fd, EVFILT_READ, EV_DELETE.cushort, nil)
    inc n
    mk(changes[n], fd, EVFILT_WRITE, EV_DELETE.cushort, nil)
    inc n

  if fd >= 0 and fd < p.fslots.len:
    p.fslots[fd] = default(FilterSlot)
  p.submit(addr changes[0], n, fd)

proc modify*(p: Platform, fd: int, events: set[EventType],
             edgeTriggered = false, udata: pointer = nil) =
  var want: uint8 = 0
  if Read in events:  want = want or FiltRead
  if Write in events: want = want or FiltWrite
  if edgeTriggered:    want = want or FiltClear

  let slot = p.slotFor(fd)
  if slot.mask == want and slot.udata == udata:
    return  # no-op: nothing about this registration changed

  let addFlags: cushort =
    if edgeTriggered: (EV_ADD or EV_CLEAR).cushort else: EV_ADD.cushort
  # EV_CLEAR can only be changed by re-adding, and a changed udata has to ride
  # along on an actual change. In either case re-issue every wanted filter
  # instead of the deltas. (Explicit parens for clarity around the `or`.)
  let edgeChanged = (want and FiltClear) != (slot.mask and FiltClear)
  let fullReAdd = edgeChanged or (slot.udata != udata)

  var n = 0
  var changes: array[2, KEvent]

  if fullReAdd:
    if Read in events:
      mk(changes[n], fd, EVFILT_READ, addFlags, udata)
      inc n
    if Write in events:
      mk(changes[n], fd, EVFILT_WRITE, addFlags, udata)
      inc n
    if Read notin events and (slot.mask and FiltRead) != 0:
      mk(changes[n], fd, EVFILT_READ, EV_DELETE.cushort, nil)
      inc n
    if Write notin events and (slot.mask and FiltWrite) != 0:
      mk(changes[n], fd, EVFILT_WRITE, EV_DELETE.cushort, nil)
      inc n
  else:
    if Read in events and (slot.mask and FiltRead) == 0:
      mk(changes[n], fd, EVFILT_READ, addFlags, udata)
      inc n
    if Write in events and (slot.mask and FiltWrite) == 0:
      mk(changes[n], fd, EVFILT_WRITE, addFlags, udata)
      inc n
    if Read notin events and (slot.mask and FiltRead) != 0:
      mk(changes[n], fd, EVFILT_READ, EV_DELETE.cushort, nil)
      inc n
    if Write notin events and (slot.mask and FiltWrite) != 0:
      mk(changes[n], fd, EVFILT_WRITE, EV_DELETE.cushort, nil)
      inc n

  slot.mask = want
  if n > 0:
    slot.udata = udata
  p.submit(addr changes[0], n, fd)

# ── Wake ─────────────────────────────────────────────────────────────────────

proc wake*(p: Platform) {.inline.} =
  when userFilterAvailable:
    # NOTE: `flags` is 0 here, not EV_ADD — submitting the change *is* the
    # trigger. The kernel coalesces concurrent triggers, so a storm of wakes
    # can never overflow anything the way the pipe could.
    var wev: KEvent
    wev.ident  = 0
    wev.filter = EvFilterUser.cshort
    wev.flags  = 0
    wev.fflags = NoteTrigger
    wev.data   = 0
    wev.udata  = nil
    discard kevent(p.kqFd, addr wev, 1, nil, 0, nil)
  else:
    var byte: byte = 0
    discard posix.write(p.wakeWriteFd, addr byte, 1)

# ── Staged changelist recovery ───────────────────────────────────────────────

when changelistBatched:
  proc recoverChanges(p: Platform) =
    ## A staged change was rejected, so `kevent()` aborted before waiting.
    ## Re-apply the entries one at a time: the first offender is recorded for
    ## `pendingError*` and the remainder still lands, so one bad fd cannot
    ## silently drop every registration behind it. Costs one syscall per change
    ## — exactly what the unbatched implementation always paid — and only on a
    ## genuinely failing changelist.
    var i = 0
    while i < p.pending.len:
      var one = p.pending[i]
      if kevent(p.kqFd, addr one, 1, nil, 0, nil) < 0:
        if p.pendErrFd < 0:
          p.pendErrFd = p.pendingFd[i]
          p.pendErrNo = errno
      inc i
    p.pending.setLen(0)
    p.pendingFd.setLen(0)

proc pendingError*(p: Platform): (int, int) {.inline.} =
  ## `(fd, errno)` of the last rejected staged change, `(-1, 0)` when there is
  ## none. `poll()` raises on it before dispatching, which is where the
  ## pre-change `add()` used to raise from — the contract is preserved, only the
  ## timing moves to the next wait.
  (p.pendErrFd, p.pendErrNo)

# ── Polling ──────────────────────────────────────────────────────────────────

proc poll*(p: Platform, timeoutMs: int): int =
  var ts: Timespec
  var tsPtr: ptr Timespec = nil
  # Sampled lazily on the first EINTR only. Reading the clock up front would
  # add a `mach_absolute_time` to every poll iteration; EINTR is rare enough
  # that paying for two reads there and zero here is strictly better.
  var startMono = -1'i64

  if timeoutMs >= 0:
    ts.tv_sec  = Time(timeoutMs div 1000)
    ts.tv_nsec = (timeoutMs mod 1000) * 1_000_000
    tsPtr = addr ts

  var n: cint
  while true:
    when changelistBatched:
      let nChanges = p.pending.len.cint
      let chPtr: ptr KEvent = if nChanges > 0: addr p.pending[0] else: nil
    else:
      const nChanges = 0.cint
      const chPtr: ptr KEvent = nil

    n = kevent(p.kqFd, chPtr, nChanges,
               addr p.kEvents[0], p.kEvents.len.cint, tsPtr)
    if n < 0:
      if errno == EINTR:
        # Rebuild the remaining wait from the original deadline. Re-submitting
        # the same `Timespec` (as this loop used to) let a signal storm extend
        # the timeout without bound.
        if tsPtr != nil:
          if startMono < 0:
            startMono = getMonoTime().ticks div 1_000_000
          let elapsed = getMonoTime().ticks div 1_000_000 - startMono
          let remaining = timeoutMs - elapsed.int
          if remaining <= 0:
            n = 0
            break
          ts.tv_sec  = Time(remaining div 1000)
          ts.tv_nsec = (remaining mod 1000) * 1_000_000
        continue
      when changelistBatched:
        if nChanges > 0:
          p.recoverChanges()
      break

    when changelistBatched:
      if nChanges > 0:
        p.pending.setLen(0)
        p.pendingFd.setLen(0)
      if p.pendErrFd >= 0:
        let badFd = p.pendErrFd
        let badErr = p.pendErrNo
        p.pendErrFd = -1
        raise newException(OSError,
          "powpow: kevent change failed for fd " & $badFd & ": " & $strerror(badErr.cint))
    if n == 0:
      p.count = 0
      return 0
    break

  p.count = 0
  for i in 0 ..< n.int:
    let kev = addr p.kEvents[i]
    when userFilterAvailable:
      if kev.filter == EvFilterUser.cshort:
        continue  # EVFILT_USER carries no state to drain
    else:
      if kev.ident.int == p.wakeReadFd:
        var buf: array[64, byte]
        discard posix.read(p.wakeReadFd, addr buf[0], 64)
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
