## powpow/loop.nim — The event loop.
##
## A single-threaded, non-blocking event loop that drives fd I/O,
## one-shot and repeating timers, deferred callbacks, and idle handlers.

import platform
import types
export types

import std/[times, tables, deques, heapqueue, sets]

# ── Timer internals ──────────────────────────────────────────────────────────

type
  TimerEntry = object
    id:       TimerId
    deadline: int64      # absolute time in ms (epochMono)
    interval: int64      # ms; 0 = one-shot
    callback: TimerCallback
    cancelled: bool

proc `<`(a, b: TimerEntry): bool =
  a.deadline < b.deadline

# Millisecond clock — uses std/monotimes for a cheap, monotonic clock.
import std/monotimes

proc monoMs(): int64 {.inline.} =
  ## Current monotonic time in milliseconds.
  getMonoTime().ticks div 1_000_000  # ns → ms

# ── Watcher ──────────────────────────────────────────────────────────────────

type
  FdWatcher* = object
    ## A registered fd watcher.
    fd*:       int
    events*:   set[EventType]
    callback*: FdCallback

# ── Loop ─────────────────────────────────────────────────────────────────────

type
  Loop* = ref object
    ## The event loop.
    platform*: Platform          ## platform backend
    fdWatchers:  Table[int, FdWatcher]   ## fd → watcher
    timers:      HeapQueue[TimerEntry]
    nextTimerId: int
    cancelled:   HashSet[TimerId]          ## lazily cancelled timer ids
    deferred:    Deque[Callback]        ## pending deferred calls
    idleCbs:     Table[int, Callback]      ## idle handlers (id → callback)
    nextIdleId:  int
    running*:    bool
    stopFlag:    bool

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc newLoop*(): Loop =
  ## Create a new event loop.
  Loop(
    platform:    Platform.init(),
    fdWatchers:  initTable[int, FdWatcher](64),
    timers:      initHeapQueue[TimerEntry](),
    nextTimerId: 0,
    cancelled:   initHashSet[TimerId](),
    deferred:    initDeque[Callback](16),
    idleCbs:     initTable[int, Callback](),
    nextIdleId:  0,
    running:     false,
    stopFlag:    false,
  )

proc close*(loop: Loop) =
  ## Destroy the loop and release the platform backend.
  loop.platform.close()
  loop.fdWatchers.clear()

# ── fd watchers ──────────────────────────────────────────────────────────────

proc register*(loop: Loop, fd: int, events: set[EventType],
               callback: FdCallback, edgeTriggered = false) =
  ## Register an fd for the given `events` with a `callback`.
  let watcher = FdWatcher(fd: fd, events: events, callback: callback)
  loop.fdWatchers[fd] = watcher
  loop.platform.add(fd, events, edgeTriggered)

proc unregister*(loop: Loop, fd: int) =
  ## Unregister an fd watcher and remove it from the platform.
  if fd in loop.fdWatchers:
    loop.platform.remove(fd)
    loop.fdWatchers.del(fd)

proc modify*(loop: Loop, fd: int, events: set[EventType],
             edgeTriggered = false) =
  ## Change the events an fd watcher is interested in.
  if fd in loop.fdWatchers:
    loop.fdWatchers[fd].events = events
    loop.platform.modify(fd, events, edgeTriggered)

# ── deferred calls ──────────────────────────────────────────────────────────

proc deferCall*(loop: Loop, cb: Callback) =
  ## Schedule `cb` to be called at the beginning of the next loop iteration.
  loop.deferred.addLast(cb)

# ── timers ───────────────────────────────────────────────────────────────────

proc addTimer*(loop: Loop, delayMs: int, callback: TimerCallback): TimerId =
  ## Schedule a one-shot timer that fires after `delayMs` milliseconds.
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
  ## Schedule a repeating timer that fires every `intervalMs` milliseconds.
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
  ## Cancel a pending timer. The timer will not fire.
  ## (Lazy cancellation — the entry is skipped when it reaches the top.)
  loop.cancelled.incl(id)

# ── idle handlers ────────────────────────────────────────────────────────────

proc addIdle*(loop: Loop, cb: Callback): int =
  ## Register a callback that runs when no other events are pending.
  ## Returns an id that can be passed to `removeIdle`.
  inc loop.nextIdleId
  result = loop.nextIdleId
  loop.idleCbs[result] = cb

proc removeIdle*(loop: Loop, id: int) =
  ## Remove a previously registered idle callback by its id.
  loop.idleCbs.del(id)

# ── control ──────────────────────────────────────────────────────────────────

proc stop*(loop: Loop) =
  ## Stop the loop after the current iteration completes.
  loop.stopFlag = true

proc isRunning*(loop: Loop): bool =
  loop.running

# ── internal: process timers ─────────────────────────────────────────────────

proc processTimers(loop: Loop) =
  ## Fire all expired timers.
  let now = monoMs()
  while loop.timers.len > 0:
    var top = loop.timers[0]
    if top.deadline > now:
      break
    discard loop.timers.pop()
    if top.id in loop.cancelled:
      loop.cancelled.excl(top.id)
      continue
    top.callback(top.id.int)
    # Reschedule interval timers
    if top.interval > 0:
      top.deadline = now + top.interval
      loop.timers.push(top)

proc timerTimeout(loop: Loop): int =
  ## Calculate the timeout for the next poll in milliseconds.
  ## Returns -1 (block indefinitely) if there are no timers.
  if loop.timers.len == 0:
    return -1
  let now = monoMs()
  let wait = loop.timers[0].deadline - now
  if wait <= 0: return 0
  return wait.int

# ── internal: process deferred ───────────────────────────────────────────────

proc processDeferred(loop: Loop) =
  ## Execute all deferred callbacks.
  while loop.deferred.len > 0:
    let cb = loop.deferred.popFirst()
    cb()

# ── main loop ────────────────────────────────────────────────────────────────

proc poll*(loop: Loop, timeoutMs: int = -1) {.inline.} =
  ## Run a single iteration of the loop:
  ## 1. Process deferred callbacks
  ## 2. Process expired timers
  ## 3. Poll the platform for I/O events
  ## 4. Dispatch I/O events to registered watchers
  ## 5. Run idle handlers if nothing happened
  # 1 — deferred
  processDeferred(loop)
  if loop.stopFlag: return

  # 2 — timers
  processTimers(loop)
  if loop.stopFlag: return

  # 3 — compute timeout and poll
  var timeout = timeoutMs
  if timeout < 0:
    timeout = timerTimeout(loop)

  let nEvents = loop.platform.poll(timeout)

  # 4 — dispatch I/O events
  for i in 0 ..< nEvents:
    let pev = loop.platform.events[i]
    if pev.fd in loop.fdWatchers:
      let w = loop.fdWatchers[pev.fd]
      w.callback(pev.fd, pev.events)
  if loop.stopFlag: return

  # 5 — post-poll timers (some may have expired during the poll)
  processTimers(loop)
  if loop.stopFlag: return

  # 6 — idle handlers (only if no events fired this iteration)
  if nEvents == 0 and loop.idleCbs.len > 0:
    for cb in loop.idleCbs.values:
      cb()

proc run*(loop: Loop) =
  ## Run the event loop until `stop()` is called.
  loop.running = true
  loop.stopFlag = false
  while not loop.stopFlag:
    loop.poll()
  loop.running = false

proc runOnce*(loop: Loop) =
  ## Run exactly one iteration of the event loop.
  loop.running = true
  loop.poll()
  loop.running = false
