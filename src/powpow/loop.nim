# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/loop.nim — The event loop.
##
## A single-threaded, non-blocking event loop that drives fd I/O,
## one-shot and repeating timers, deferred callbacks, and idle handlers.
## Includes a self-pipe wake mechanism for thread-safe stop().

import std/[tables, deques, heapqueue, sets, monotimes]

import ./platform, ./types
export types

when defined(windows):
  proc closesocket(s: int): cint {.importc: "closesocket", stdcall, dynlib: "ws2_32.dll".}
else:
  import std/posix

# ── Timer internals ──────────────────────────────────────────────────────────

const
  MaxTimerBatch = 256
    ## Maximum timers to fire per poll iteration. Limits I/O starvation.

type
  TimerEntry = object
    id:       TimerId
    deadline: int64      # absolute time in ms (epochMono)
    interval: int64      # ms; 0 = one-shot
    callback: TimerCallback
    cancelled: bool

proc `<`(a, b: TimerEntry): bool =
  a.deadline < b.deadline

proc monoMs(): int64 {.inline.} =
  getMonoTime().ticks div 1_000_000

# ── Watcher ──────────────────────────────────────────────────────────────────

type
  FdWatcher* = object
    fd*:            int
    events*:        set[EventType]
    callback*:      FdCallback
    edgeTriggered*: bool
    gen:            int

# ── Loop ─────────────────────────────────────────────────────────────────────

type
  Loop* = ref object
    platform*:   Platform
    fdWatchers:  Table[int, FdWatcher]
    nextGen:     int
    timers:      HeapQueue[TimerEntry]
    nextTimerId: int
    cancelled:   HashSet[TimerId]
    deferred:    Deque[Callback]
    idleCbs:     Table[int, Callback]
    nextIdleId:  int
    running:     bool
    stopFlag:    bool
    bufPool*:    seq[ptr UncheckedArray[byte]]

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc newLoop*(): Loop =
  Loop(
    platform:    Platform.init(),
    fdWatchers:  initTable[int, FdWatcher](256),
    nextGen:     1,
    timers:      initHeapQueue[TimerEntry](),
    nextTimerId: 0,
    cancelled:   initHashSet[TimerId](),
    deferred:    initDeque[Callback](16),
    idleCbs:     initTable[int, Callback](),
    nextIdleId:  0,
    running:     false,
    stopFlag:    false,
    bufPool:     @[],
  )

proc close*(loop: Loop) =
  for fd in loop.fdWatchers.keys:
    when defined(windows):
      discard closesocket(fd)
    else:
      discard posix.close(fd.cint)
  loop.fdWatchers.clear()
  for buf in loop.bufPool:
    deallocShared(buf)
  loop.bufPool.setLen(0)
  loop.platform.close()

# ── fd watchers ──────────────────────────────────────────────────────────────

proc register*(loop: Loop, fd: int, events: set[EventType],
               callback: FdCallback, edgeTriggered = false) =
  let gen = loop.nextGen
  inc loop.nextGen
  let watcher = FdWatcher(fd: fd, events: events, callback: callback,
                          edgeTriggered: edgeTriggered, gen: gen)
  loop.fdWatchers[fd] = watcher
  loop.platform.add(fd, events, edgeTriggered, cast[pointer](gen))

proc unregister*(loop: Loop, fd: int) =
  if fd in loop.fdWatchers:
    loop.platform.remove(fd)
    loop.fdWatchers.del(fd)

proc modify*(loop: Loop, fd: int, events: set[EventType]) =
  if fd in loop.fdWatchers:
    loop.fdWatchers[fd].events = events
    let et = loop.fdWatchers[fd].edgeTriggered
    let gen = loop.fdWatchers[fd].gen
    loop.platform.modify(fd, events, et, cast[pointer](gen))

# ── deferred calls ──────────────────────────────────────────────────────────

proc deferCall*(loop: Loop, cb: Callback) =
  loop.deferred.addLast(cb)

# ── timers ───────────────────────────────────────────────────────────────────

proc addTimer*(loop: Loop, delayMs: int, callback: TimerCallback): TimerId =
  inc loop.nextTimerId
  result = TimerId(loop.nextTimerId)
  loop.timers.push(TimerEntry(
    id:       result,
    deadline: monoMs() + delayMs.int64,
    interval: 0,
    callback: callback,
    cancelled: false,
  ))

proc addInterval*(loop: Loop, intervalMs: int,
                  callback: TimerCallback): TimerId =
  inc loop.nextTimerId
  result = TimerId(loop.nextTimerId)
  loop.timers.push(TimerEntry(
    id:       result,
    deadline: monoMs() + intervalMs.int64,
    interval: intervalMs.int64,
    callback: callback,
    cancelled: false,
  ))

proc cancelTimer*(loop: Loop, id: TimerId) =
  loop.cancelled.incl(id)

# ── idle handlers ────────────────────────────────────────────────────────────

proc addIdle*(loop: Loop, cb: Callback): int =
  inc loop.nextIdleId
  result = loop.nextIdleId
  loop.idleCbs[result] = cb

proc removeIdle*(loop: Loop, id: int) =
  loop.idleCbs.del(id)

# ── control ──────────────────────────────────────────────────────────────────

proc stop*(loop: Loop) =
  loop.stopFlag = true
  loop.platform.wake()

proc isRunning*(loop: Loop): bool =
  loop.running

# ── internal: process timers ─────────────────────────────────────────────────

proc processTimers(loop: Loop; now: int64) =
  var batch = 0
  while loop.timers.len > 0 and batch < MaxTimerBatch:
    var top = loop.timers[0]
    if top.deadline > now:
      break
    discard loop.timers.pop()
    inc batch
    if top.id in loop.cancelled:
      loop.cancelled.excl(top.id)
      continue
    top.callback(top.id.int)
    if top.interval > 0:
      top.deadline = now + top.interval
      loop.timers.push(top)

  # Prune cancelled set when it grows large
  if loop.cancelled.len > loop.timers.len * 2 + 16:
    loop.cancelled.clear()

proc timerTimeout(loop: Loop; now: int64): int =
  if loop.timers.len == 0:
    return -1
  let wait = loop.timers[0].deadline - now
  if wait <= 0: return 0
  return wait.int

# ── internal: process deferred ───────────────────────────────────────────────

proc processDeferred(loop: Loop) =
  while loop.deferred.len > 0:
    let cb = loop.deferred.popFirst()
    cb()

# ── main loop ────────────────────────────────────────────────────────────────

proc poll*(loop: Loop, timeoutMs: int = -1) {.inline.} =
  let now = monoMs()

  processDeferred(loop)
  if loop.stopFlag: return

  processTimers(loop, now)
  if loop.stopFlag: return

  var timeout = timeoutMs
  if timeout < 0:
    timeout = timerTimeout(loop, now)

  let nEvents = loop.platform.poll(timeout)

  for i in 0 ..< nEvents:
    let pev = loop.platform.events[i]
    var w: ptr FdWatcher = nil
    if pev.fd in loop.fdWatchers:
      w = addr loop.fdWatchers[pev.fd]
    if w != nil and w.callback != nil:
      if cast[int](pev.udata) == w.gen:
        w.callback(pev.fd, pev.events)
  if loop.stopFlag: return

  let now2 = monoMs()
  processTimers(loop, now2)
  if loop.stopFlag: return

  if nEvents == 0 and loop.idleCbs.len > 0:
    for cb in loop.idleCbs.values:
      cb()

proc run*(loop: Loop) =
  loop.running = true
  loop.stopFlag = false
  while not loop.stopFlag:
    loop.poll()
  loop.running = false

proc runOnce*(loop: Loop) =
  loop.running = true
  loop.poll()
  loop.running = false
