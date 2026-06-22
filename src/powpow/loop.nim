# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## This module implements the core event loop and timer wheel. It can be used to build custom event-driven
## applications or as the foundation for higher-level abstractions like HTTP servers, WebSocket servers, etc.
## 
## The loop uses a hierarchical timer wheel for efficient timer management, and supports edge-triggered I/O events.
## The API is designed to be minimal and efficient, with a focus on low-latency event handling and minimal overhead.

import std/[tables, deques, sets, monotimes]

import ./platform, ./types
export types

when defined(windows):
  proc closesocket(s: int): cint {.importc: "closesocket", stdcall, dynlib: "ws2_32.dll".}
else:
  import std/posix

const
  WheelSlots = 256
  WheelLevels = 4
  MaxTimerBatch = 256
  MaxIdleBatch = 64

# ── Timer wheel types ────────────────────────────────────────────────────────

type
  TimerNode = ref TimerNodeObj
  TimerNodeObj = object
    id:       TimerId
    deadline: int64
    interval: int64
    callback: TimerCallback
    cancelled: bool
    next:     TimerNode

# ── Timer wheel helpers ──────────────────────────────────────────────────────

proc monoMs(): int64 {.inline.} =
  getMonoTime().ticks div 1_000_000

# ── Watcher ──────────────────────────────────────────────────────────────────

type
  FdWatcher* = ref object
    fd*:            int
    events*:        set[EventType]
    callback*:      FdCallback
    edgeTriggered*: bool
    gen:            int
    alive:          bool

# ── Loop ─────────────────────────────────────────────────────────────────────

type
  Loop* = ref object
    platform*:     Platform
    fdWatchers:    Table[int, FdWatcher]
    nextGen:       int
    wheel:         array[4, array[256, TimerNode]]
    wheelBase:     int64
    totalTimers:   int
    nextTimerId:   int
    cancelled:     HashSet[TimerId]
    deferred:      Deque[Callback]
    idleCbs:       Table[int, Callback]
    nextIdleId:    int
    deadCount:     int
    fdWatcherPool: seq[FdWatcher]
    running:       bool
    stopFlag:      bool
    bufPool*:      seq[ptr UncheckedArray[byte]]

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc newLoop*(): Loop =
  Loop(
    platform:    Platform.init(),
    fdWatchers:  initTable[int, FdWatcher](256),
    nextGen:     1,
    wheelBase:   monoMs(),
    totalTimers: 0,
    nextTimerId: 0,
    cancelled:   initHashSet[TimerId](),
    deferred:    initDeque[Callback](16),
    idleCbs:     initTable[int, Callback](),
    nextIdleId:  0,
    deadCount:   0,
    fdWatcherPool: @[],

    running:     false,
    stopFlag:    false,
    bufPool:     @[],
  )

proc close*(loop: Loop) =
  for fd, w in loop.fdWatchers:
    if w.alive:
      when defined(windows):
        discard closesocket(fd)
      else:
        discard posix.close(fd.cint)
  loop.fdWatchers.clear()
  loop.deadCount = 0
  for buf in loop.bufPool:
    deallocShared(buf)
  loop.bufPool.setLen(0)
  loop.platform.close()

# ── Timer wheel ──────────────────────────────────────────────────────────────

proc addToWheel(loop: Loop; node: TimerNode) {.inline.} =
  let diff = node.deadline - loop.wheelBase
  if diff < 256:
    let slot = (node.deadline and 0xFF).int
    node.next = loop.wheel[0][slot]
    loop.wheel[0][slot] = node
  elif diff < 65536:
    let slot = ((node.deadline shr 8) and 0xFF).int
    node.next = loop.wheel[1][slot]
    loop.wheel[1][slot] = node
  elif diff < 16777216:
    let slot = ((node.deadline shr 16) and 0xFF).int
    node.next = loop.wheel[2][slot]
    loop.wheel[2][slot] = node
  else:
    let slot = ((node.deadline shr 24) and 0xFF).int
    node.next = loop.wheel[3][slot]
    loop.wheel[3][slot] = node
  inc loop.totalTimers

proc cascade(loop: Loop; level: int) {.inline.} =
  let slot = ((loop.wheelBase shr (level * 8)) and 0xFF).int
  var node = loop.wheel[level][slot]
  if node == nil: return
  loop.wheel[level][slot] = nil
  while node != nil:
    let next = node.next
    node.next = nil
    addToWheel(loop, node)
    node = next

# ── fd watchers ──────────────────────────────────────────────────────────────

proc register*(loop: Loop, fd: int, events: set[EventType],
               callback: FdCallback, edgeTriggered = false) =
  let gen = loop.nextGen
  inc loop.nextGen
  if fd in loop.fdWatchers:
    let old = loop.fdWatchers[fd]
    if old.alive:
      old.alive = false
      inc loop.deadCount
      loop.fdWatcherPool.add(old)
  let watcher = if loop.fdWatcherPool.len > 0:
    let w = loop.fdWatcherPool.pop()
    w.fd = fd; w.events = events; w.callback = callback
    w.edgeTriggered = edgeTriggered; w.gen = gen; w.alive = true
    w
  else:
    FdWatcher(
      fd: fd, events: events, callback: callback,
      edgeTriggered: edgeTriggered, gen: gen, alive: true)
  loop.fdWatchers[fd] = watcher
  loop.platform.add(fd, events, edgeTriggered, cast[pointer](watcher))
  loop.platform.ensureCapacity(loop.fdWatchers.len)

proc unregister*(loop: Loop, fd: int) =
  if fd in loop.fdWatchers:
    let w = loop.fdWatchers[fd]
    if not w.alive: return
    w.alive = false
    inc loop.deadCount
    loop.fdWatcherPool.add(w)
    loop.platform.remove(fd)

proc unregisterFd*(loop: Loop, fd: int) =
  ## Remove fd watcher without platform syscall.
  ## The fd was already closed by the caller, and the OS removes it
  ## from epoll/kqueue automatically. Only cleans up in-memory state.
  if fd in loop.fdWatchers:
    let w = loop.fdWatchers[fd]
    w.alive = false
    inc loop.deadCount
    loop.fdWatcherPool.add(w)
    loop.fdWatchers.del(fd)

proc modify*(loop: Loop, fd: int, events: set[EventType]) =
  if fd in loop.fdWatchers:
    let w = loop.fdWatchers[fd]
    if w.alive:
      w.events = events
      loop.platform.modify(fd, events, w.edgeTriggered, cast[pointer](w))

# ── deferred calls ──────────────────────────────────────────────────────────

proc deferCall*(loop: Loop, cb: Callback) =
  loop.deferred.addLast(cb)

# ── timers ───────────────────────────────────────────────────────────────────

proc addTimer*(loop: Loop, delayMs: int, callback: TimerCallback): TimerId =
  inc loop.nextTimerId
  result = TimerId(loop.nextTimerId)
  let node = TimerNode(
    id:       result,
    deadline: monoMs() + delayMs.int64,
    interval: 0,
    callback: callback,
    cancelled: false,
  )
  addToWheel(loop, node)

proc addInterval*(loop: Loop, intervalMs: int,
                  callback: TimerCallback): TimerId =
  inc loop.nextTimerId
  result = TimerId(loop.nextTimerId)
  let node = TimerNode(
    id:       result,
    deadline: monoMs() + intervalMs.int64,
    interval: intervalMs.int64,
    callback: callback,
    cancelled: false,
  )
  addToWheel(loop, node)

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
  if loop.totalTimers == 0:
    loop.wheelBase = now
    return
  # Advance wheelBase to now, cascading at boundaries along the way
  var t = loop.wheelBase
  while t < now:
    inc t
    if (t and 0xFF) == 0:
      cascade(loop, 1)
    if (t and 0xFFFF) == 0:
      cascade(loop, 2)
    if (t and 0xFFFFFF) == 0:
      cascade(loop, 3)
  loop.wheelBase = now

  # Fire all expired Level-0 timers up to batch limit.
  # Walk each slot's linked list and remove only expired nodes.
  # Future nodes (e.g. re-added intervals) stay in place.
  var batch = 0
  for slot in 0 ..< 256:
    if batch >= MaxTimerBatch:
      break
    var prev: TimerNode = nil
    var node = loop.wheel[0][slot]
    while node != nil and batch < MaxTimerBatch:
      let next = node.next
      if node.deadline <= now:
        # Remove this expired node from the list
        if prev == nil:
          loop.wheel[0][slot] = next
        else:
          prev.next = next
        node.next = nil
        inc batch
        if node.id in loop.cancelled:
          loop.cancelled.excl(node.id)
          dec loop.totalTimers
        else:
          node.callback(node.id.int)
          if node.interval > 0:
            node.deadline = now + node.interval
            addToWheel(loop, node)
          else:
            dec loop.totalTimers
      else:
        prev = node
      node = next

  if loop.cancelled.len > loop.totalTimers * 2 + 16:
    loop.cancelled.clear()

proc timerTimeout(loop: Loop; now: int64): int =
  if loop.totalTimers == 0:
    return -1
  if loop.wheelBase < now:
    return 0

  var earliest = int64.high
  for level in 0 ..< 4:
    for i in 0 ..< 256:
      let n = loop.wheel[level][i]
      if n != nil and n.deadline < earliest:
        earliest = n.deadline

  if earliest == int64.high:
    return -1
  let wait = earliest - now
  if wait <= 0: return 0
  if wait > int64(high(int)):
    return high(int)
  return wait.int

# ── internal: process deferred ───────────────────────────────────────────────

proc processDeferred(loop: Loop) {.inline.} =
  while loop.deferred.len > 0:
    let cb = loop.deferred.popFirst()
    cb()

# ── internal: sweep dead watchers ────────────────────────────────────────────

proc sweepDead(loop: Loop) {.inline.} =
  if loop.deadCount > 64:
    var dead: seq[int]
    for fd, w in loop.fdWatchers:
      if not w.alive:
        dead.add(fd)
    for fd in dead:
      loop.fdWatchers.del(fd)
    loop.deadCount = 0


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
    let w = cast[FdWatcher](pev.udata)
    if w != nil and w.alive:
      w.callback(w.fd, pev.events)
  if loop.stopFlag: return

  let now2 = monoMs()
  processTimers(loop, now2)
  if loop.stopFlag: return

  sweepDead(loop)

  if nEvents == 0 and loop.idleCbs.len > 0:
    var batch = 0
    for cb in loop.idleCbs.values:
      if batch >= MaxIdleBatch: break
      cb()
      inc batch

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
