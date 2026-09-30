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
## Four backend-specific optimisations are layered on top of plain kqueue(2):
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
## 3. **EVFILT_USER wake.** Where std/kqueue exposes EVFILT_USER, the wake pipe
##    is replaced by a user knote: no fds consumed, and nothing to drain in the
##    poll path. The pipe drain also had a lost-wakeup edge — it read 8 bytes
##    while `wake()` writes 1 byte per call, and `EV_CLEAR` deactivates the
##    knote after the first report, so 9+ piled-up wake bytes left the pipe
##    readable with no edge left to re-fire on.
##
## 4. **Allocation-free event decode.** `poll()` walks the kernel's event array
##    in place — one hoisted `addr` per event, so no 32-byte `KEvent` is copied —
##    and decodes the filter with a `case`. That is one bounds check per event
##    instead of four and no allocations, which matters more than it looks
##    because Nim's `-d:release` keeps bound checks *on* (only `-d:danger` drops
##    them). The remaining per-event work is one `EV_ERROR` test (not two) and
##    no `uint -> int` range check on `ident`. Note what is deliberately *not*
##    done here: hoisting the seq headers and counter into locals. It removes
##    five heap loads per event from the generated C and measures ~3% slower —
##    see the long comment on the decode loop.

import ../types
import std/[kqueue, posix, monotimes]

const
  EventCapacityMin = 512
  EventCapacityMax = 16384

const
  ## Stage registration changes in a changelist flushed with the next wait.
  ## macOS only — FreeBSD/NetBSD/OpenBSD keep the immediate `kevent()` path.
  changelistBatched = defined(macosx)
  ## std/kqueue declares EVFILT_USER and NOTE_TRIGGER for exactly these
  ## platforms (its own comment notes OpenBSD and NetBSD lack EVFILT_USER), so
  ## this guard must not be widened: the filter number differs per BSD, which is
  ## why the constant is taken from std/kqueue instead of hardcoded.
  userFilterAvailable =
    defined(macosx) or defined(freebsd) or defined(dragonfly)

# ── Per-fd knote state ────────────────────────────────────────────────────────

const
  FiltRead  = 1'u8   ## EVFILT_READ is registered
  FiltWrite = 2'u8   ## EVFILT_WRITE is registered
  FiltClear = 4'u8   ## registered edge-triggered (EV_CLEAR)
  FiltAny    = FiltRead or FiltWrite

  FiltReadK  = cshort(EVFILT_READ)
  FiltWriteK = cshort(EVFILT_WRITE)

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
    scratch:    FilterSlot       ## slot used for fds outside the table
    pendErrFd:  int              ## fd of the last rejected change, -1 when none
    pendErrNo:  int
    when changelistBatched:
      ## `pending` is handed to `kevent()` as a contiguous `struct kevent[]`,
      ## so it MUST be a plain seq[KEvent] with nothing interleaved between
      ## entries. An earlier revision stored `{ev: KEvent, fd: int}` per entry
      ## to halve the seq headers touched per append — but that struct is 40
      ## bytes against kqueue's 32, so the kernel read the fd as part of the
      ## next event and every staged batch after the first was garbage.
      ## `pendingFd` is a parallel array purely for error reporting.
      pending: seq[KEvent]
      pendingFd: seq[int]

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
  when changelistBatched:
    result.pending = newSeqOfCap[KEvent](32)
    result.pendingFd = newSeqOfCap[int](32)

  when userFilterAvailable:
    # `ident` is ignored for EVFILT_USER.
    var wev = KEvent(ident: 0, filter: EVFILT_USER, flags: EV_ADD or EV_CLEAR,
                      fflags: 0, data: 0, udata: nil)
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
    if flags >= 0:
      discard fcntl(result.wakeReadFd, F_SETFL, flags or O_NONBLOCK)
    let wflags = fcntl(result.wakeWriteFd, F_GETFL, 0)
    if wflags >= 0:
      discard fcntl(result.wakeWriteFd, F_SETFL, wflags or O_NONBLOCK)

    var wev = KEvent(ident: result.wakeReadFd.uint, filter: EVFILT_READ,
                      flags: EV_ADD or EV_CLEAR, fflags: 0, data: 0, udata: nil)
    if kevent(result.kqFd, addr wev, 1, nil, 0, nil) < 0:
      discard posix.close(result.wakeReadFd)
      discard posix.close(result.wakeWriteFd)
      discard posix.close(result.kqFd)
      raise newException(OSError, "powpow: kevent ADD failed for wake fd")

proc close*(p: Platform) =
  when changelistBatched:
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
  # `poll` hands the kernel `kEvents.len` as the eventlist size and then decodes
  # into `events`, so `events` must never be the smaller of the two. Growing
  # them under independent guards (rather than one shared `target > events.len`
  # test) keeps `events.len >= kEvents.len` even if a future change resizes only
  # one of them, which is the invariant `poll`'s decode loop relies on.
  if target > p.kEvents.len:
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

proc mkev(ev: var KEvent, fd: int, filter: cshort, flags: cushort,
          udata: pointer) {.inline, noSideEffect.} =
  ## Fill in place. Returning a `struct kevent` by value instead measured
  ## ~5-7% slower on the add/remove and modify micro-benchmarks (322 vs 307
  ## ns/op): the return goes through an sret temporary because the destination
  ## is `changes[n]` with a runtime `n`.
  ev.ident  = fd.uint
  ev.filter = filter
  ev.flags  = flags
  ev.fflags = 0
  ev.data   = 0
  ev.udata  = udata

proc submit(p: Platform, changes: openArray[KEvent], n: int, fd: int) =
  ## Apply the first `n` of `changes` for `fd`.
  ##
  ## `openArray` keeps the caller's `array[2, KEvent]` copy-free, and callers
  ## pass the array itself with the count alongside (`submit(changes, n, fd)`).
  ## Two plausible-looking alternatives are both wrong, and were measured:
  ##   - `changes[0 ..< n]` — a runtime-length slice of the fixed-size array
  ##     measured 563-592 ns/op on the add+remove and modify micro-benchmarks
  ##     versus 318-336 for the form above, ~78% slower, because a runtime slice
  ##     of a fixed-size array does not resolve to a compile-time view.
  ##   - `toOpenArray(0, n)` — inclusive of `n`, so it hands over one element
  ##     past the 2-element array. At n == 1 that silently staged a garbage
  ##     duplicate changelist entry on every single-filter registration.
  ## On macOS the changes are staged and flushed with the next wait; elsewhere
  ## they go out in one `kevent()` call so a read+write pair stays a single
  ## syscall.
  when changelistBatched:
    let arr = cast[ptr UncheckedArray[KEvent]](unsafeAddr changes[0])
    for i in 0 ..< n:
      p.pending.add arr[i]
      p.pendingFd.add fd
  else:
    if n > 0:
      if kevent(p.kqFd, unsafeAddr changes[0], n.cint, nil, 0, nil) < 0:
        raise newException(OSError,
          "powpow: kevent change failed for fd " & $fd & ": " & $strerror(errno))

proc wantMask(events: set[EventType], edgeTriggered: bool): uint8
    {.inline, noSideEffect.} =
  ## Which filters a knote needs to cover `events`. One definition shared by
  ## `add` and `modify` so the two can never disagree about what "already
  ## registered" means — that disagreement would silently skip a knote.
  ##
  ## Two independent bit tests rather than a `case`: the set's bits are
  ## independent, so there is no single-value dispatch to jump-table, and a
  ## `case` would still need a fallback branch for combinations like
  ## `{Read, Error}` that the hot path never produces.
  result = 0
  if Read in events:  result = result or FiltRead
  if Write in events: result = result or FiltWrite
  if edgeTriggered:    result = result or FiltClear

proc add*(p: Platform, fd: int, events: set[EventType],
          edgeTriggered = false, udata: pointer = nil) =
  let want = wantMask(events, edgeTriggered)
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
  let addFlags: cushort =
    if edgeTriggered: (EV_ADD or EV_CLEAR).cushort else: EV_ADD.cushort

  var n = 0
  var changes: array[2, KEvent]
  if Read in events:
    mkev(changes[n], fd, FiltReadK, addFlags, udata)
    inc n
  if Write in events:
    mkev(changes[n], fd, FiltWriteK, addFlags, udata)
    inc n

  slot.mask = want
  if n > 0:
    slot.udata = udata
  p.submit(changes, n, fd)

proc remove*(p: Platform, fd: int) =
  let slot = p.slotFor(fd)
  let have = slot.mask and FiltAny

  var n = 0
  var changes: array[2, KEvent]
  if (have and FiltRead) != 0:
    mkev(changes[n], fd, FiltReadK, EV_DELETE.cushort, nil)
    inc n
  if (have and FiltWrite) != 0:
    mkev(changes[n], fd, FiltWriteK, EV_DELETE.cushort, nil)
    inc n
  if n == 0:
    # Nothing tracked for this fd (never registered through `add`, or its state
    # was already cleared). Blind-delete both filters in a single `kevent()`
    # rather than leak a knote if the bookkeeping is ever wrong; this is the
    # defensive path and does not run for a normally-registered fd.
    mkev(changes[0], fd, FiltReadK, EV_DELETE.cushort, nil)
    mkev(changes[1], fd, FiltWriteK, EV_DELETE.cushort, nil)
    n = 2

  if fd >= 0 and fd < p.fslots.len:
    p.fslots[fd] = default(FilterSlot)
  p.submit(changes, n, fd)

proc modify*(p: Platform, fd: int, events: set[EventType],
             edgeTriggered = false, udata: pointer = nil) =
  let want = wantMask(events, edgeTriggered)
  let slot = p.slotFor(fd)
  if slot.mask == want and slot.udata == udata:
    return  # no-op: nothing about this registration changed

  # EV_CLEAR can only be changed by re-adding, and a changed udata has to ride
  # along on an actual change. In either case re-issue every wanted filter
  # instead of the deltas. (Explicit parens for clarity around the `or`.)
  let edgeChanged = (want and FiltClear) != (slot.mask and FiltClear)
  let fullReAdd = edgeChanged or (slot.udata != udata)

  let addFlags: cushort =
    if edgeTriggered: (EV_ADD or EV_CLEAR).cushort else: EV_ADD.cushort

  var n = 0
  var changes: array[2, KEvent]

  if fullReAdd:
    # At most one entry per filter: a filter that is wanted is re-added, a
    # filter that is not is deleted, never both.
    if Read in events:
      mkev(changes[n], fd, FiltReadK, addFlags, udata)
      inc n
    if Write in events:
      mkev(changes[n], fd, FiltWriteK, addFlags, udata)
      inc n
  else:
    if Read in events and (slot.mask and FiltRead) == 0:
      mkev(changes[n], fd, FiltReadK, addFlags, udata)
      inc n
    if Write in events and (slot.mask and FiltWrite) == 0:
      mkev(changes[n], fd, FiltWriteK, addFlags, udata)
      inc n

  if Read notin events and (slot.mask and FiltRead) != 0:
    mkev(changes[n], fd, FiltReadK, EV_DELETE.cushort, nil)
    inc n
  if Write notin events and (slot.mask and FiltWrite) != 0:
    mkev(changes[n], fd, FiltWriteK, EV_DELETE.cushort, nil)
    inc n

  slot.mask = want
  if n > 0:
    slot.udata = udata
  p.submit(changes, n, fd)

# ── Wake ─────────────────────────────────────────────────────────────────────

proc wake*(p: Platform) {.inline.} =
  when userFilterAvailable:
    # NOTE: `flags` is 0 here, not EV_ADD — submitting the change *is* the
    # trigger. The kernel coalesces concurrent triggers, so a storm of wakes
    # can never overflow anything the way the pipe could.
    var wev = KEvent(ident: 0, filter: EVFILT_USER, flags: 0,
                      fflags: NOTE_TRIGGER, data: 0, udata: nil)
    discard kevent(p.kqFd, addr wev, 1, nil, 0, nil)
  else:
    var byte: byte = 0
    discard posix.write(p.wakeWriteFd, addr byte, 1)

# ── Staged changelist recovery ───────────────────────────────────────────────

when changelistBatched:
  proc recoverChanges(p: Platform) =
    ## A staged change was rejected, so `kevent()` aborted before waiting.
    ## Re-apply the entries one at a time: the first offender is recorded and
    ## the remainder still lands, so one bad fd cannot silently drop every
    ## registration behind it. Costs one syscall per change — exactly what the
    ## unbatched implementation always paid — and only on a genuinely failing
    ## changelist.
    for i in 0 ..< p.pending.len:
      var one = p.pending[i]
      if kevent(p.kqFd, addr one, 1, nil, 0, nil) < 0 and p.pendErrFd < 0:
        p.pendErrFd = p.pendingFd[i]
        p.pendErrNo = errno
    p.pending.setLen(0)
    p.pendingFd.setLen(0)

# ── Polling ──────────────────────────────────────────────────────────────────

proc poll*(p: Platform, timeoutMs: int): int =
  var ts: Timespec
  var tsPtr: ptr Timespec = nil
  # Sampled lazily on the first EINTR only. Reading the clock up front would
  # add a `mach_absolute_time` + `mach_timebase_info` to every poll iteration;
  # EINTR is rare enough that paying for two reads there and zero here is
  # strictly better.
  var startMono = -1'i64

  if timeoutMs >= 0:
    ts.tv_sec  = Time(timeoutMs div 1000)
    ts.tv_nsec = (timeoutMs mod 1000) * 1_000_000
    tsPtr = addr ts

  var n: cint
  p.count = 0
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
            return 0
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
      # A staged change was rejected; surface it here, which is where the
      # pre-change `add()` used to raise from — same contract, the timing just
      # moves to the next wait. Raised before dispatch so a failed registration
      # never reports as a live event.
      if p.pendErrFd >= 0:
        let badFd = p.pendErrFd
        let badErr = p.pendErrNo
        p.pendErrFd = -1
        raise newException(OSError,
          "powpow: kevent change failed for fd " & $badFd & ": " & $strerror(badErr.cint))
    if n == 0:
      return 0
    break

  # Decode in place: read `p.kEvents[i]` through a pointer so no 32-byte KEvent
  # is copied per event, and write one `PlatformEvent` per kernel event.
  #
  # Deliberately NOT hoisting `p.kEvents` / `p.events` / `p.count` into locals.
  # The generated C reloads all five from the heap on every iteration, because
  # the stores below go through a pointer into `p.events` and Nim compiles with
  # `-fno-strict-aliasing`, so clang cannot prove the two are disjoint. Hoisting
  # them by hand does remove those loads, and it is *slower*: measured
  # 90.5 -> 92.3 ns/event over a 512-event poll, consistently, across
  # interleaved runs. The reloads are hot L1 hits on the Platform object, and
  # keeping the seq headers, lengths and counter live across the loop costs more
  # in register pressure and in two extra bounds guards than the loads it saves.
  #
  # Hoisting into `seq` locals instead of raw pointers is outright broken and
  # cost an afternoon: a Nim seq of a non-GC'd element type has no refcount, so
  # `let s = p.kEvents` bit-copies the `{len, p}` header and *still* emits a
  # `=destroy` on scope exit — which then `alignedDealloc`s the very buffer
  # `p.events`/`p.kEvents` still point at. That frees the platform's own arrays
  # on the first poll(): the server answers exactly one request, then writes into
  # freed memory and spins at 100% CPU. Keep these as `seq` field reads.
  for i in 0 ..< n.int:
    let kev = addr p.kEvents[i]
    when userFilterAvailable:
      if kev.filter == EVFILT_USER:
        continue  # EVFILT_USER carries no state to drain
    else:
      if kev.ident.int == p.wakeReadFd:
        var buf: array[64, byte]
        discard posix.read(p.wakeReadFd, addr buf[0], 64)
        continue

    let flags = kev.flags
    # One EV_ERROR test, not two. EV_EOF stays an independent test: an event
    # carrying both EV_ERROR and EV_EOF must report Error *and* Hup.
    let isErr = (flags and EV_ERROR) != 0
    var evs: set[EventType] = {}
    if isErr:
      evs.incl Error
    if (flags and EV_EOF) != 0:
      evs.incl Hup
    if not isErr:
      # `case` on the kernel's filter (not an if/elif chain): EVFILT_USER and
      # the EVFILT_TIMER/VNODE traps land in `else` without an extra compare.
      case kev.filter
      of FiltReadK: evs.incl Read
      of FiltWriteK: evs.incl Write
      else: discard

    let pev = addr p.events[p.count]
    # std/kqueue declares KEvent.ident as `uint` even though the kernel field is
    # uintptr_t, so Nim's checked uint -> int conversion emitted a
    # raiseRangeErrorNoArgs per event that can never fire on any platform where
    # the two types are the same width.
    when sizeof(int) > sizeof(uint):
      pev.fd = kev.ident.int
    else:
      pev.fd = cast[int](kev.ident)
    pev.events = evs
    pev.udata = kev.udata
    inc p.count

  return p.count
