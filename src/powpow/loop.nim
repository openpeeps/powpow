# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## This module implements the core event loop and timer wheel. It can be used to build custom event-driven
## applications or as the foundation for higher-level abstractions like HTTP servers, WebSocket servers, etc.
##
## The loop uses a hierarchical timer wheel for efficient timer management, and supports edge-triggered I/O events.
## The API is designed to be minimal and efficient, with a focus on low-latency event handling and minimal overhead.
##
## Two backends share this single module, selected at compile time:
##   - readiness (default): `epoll` (Linux), `kqueue` (macOS/BSD), `iocp` (Windows), `poll` (fallback)
##   - submission (opt-in, Linux): io_uring (`when iouEnabled`), driven by operation completions.
## The timer wheel, deferred calls, posts, observers and idle handlers are identical in both.

import std/[tables, deques, sets, monotimes, bitops, sequtils, locks]
when defined(threads):
  import std/threads
import ./types
import ./net/common
export types

when iouEnabled:
  import std/posix
  import ./io/uring
  export uring
else:
  import ./platform
  export platform
  when defined(windows):
    proc closesocket(s: int): cint {.importc: "closesocket", stdcall, dynlib: "ws2_32.dll".}
  else:
    import std/posix

const
  WheelSlots = 256
  WheelLevels = 4
  MaxTimerBatch = 256
  MaxIdleBatch = 64
  MaxBufPoolSize = 1024

when iouEnabled:
  proc eventfd(initval: cuint, flags: cint): cint {.
    importc: "eventfd", header: "<sys/eventfd.h>".}
  const EFD_NONBLOCK = 0x800

  when defined(powpowBufferSelect):
    const
      ReadBufGroupSize* = 512   # buffers in the shared multishot read group
      ReadBufBgid* = 1'u16

# ── Timer wheel types ────────────────────────────────────────────────────────

type
  TimerNode = ref TimerNodeObj
  TimerNodeObj = object
    id:       TimerId
    deadline: int64
    interval: int64
    delayMs:  int64
    callback: TimerCallback
    cancelled: bool
    paused:   bool
    next:     TimerNode

# ── Watcher ──────────────────────────────────────────────────────────────────

type
  FdWatcher* = ref object
    fd*:            int
    events*:        set[EventType]
    callback*:      FdCallback
    edgeTriggered*: bool
    when iouEnabled:
      token:          uint64   # io_uring POLL_ADD user_data
      queued:         bool     # waiting in rearmQueue for an SQE slot
    gen:            int
    alive:          bool

  Observer* = ref object
    varPtr*:  ptr uint64
    lastVal:  uint64
    cb*:      ObserverCallback
    alive:    bool

when iouEnabled:
  type OpCallback* = proc(res: int32, flags: uint32) {.closure.}

# ── Loop ─────────────────────────────────────────────────────────────────────

type
  Loop* = ref object
    when iouEnabled:
      ring:        Ring
      wakeFd:      cint
      wakeToken:   uint64
      wakeArmed:   bool
      timeoutToken: uint64
      timeoutPending: bool
      timeoutDeadline: int64
      timeoutTs:   KernelTimespec
      nextToken:   uint64
      opCbs:       Table[uint64, OpCallback]
      watcherTokens: Table[uint64, int]
      writabilityHooks: seq[proc(fd: int) {.closure.}]
      writabilityTokens: Table[uint64, int]
      takeoverCbs: Table[int, proc() {.closure.}]
      rearmQueue:  seq[FdWatcher]
      reaped:      int
      when defined(powpowBufferSelect):
        bufGroup:     ptr UncheckedArray[byte]   # shared multishot read buffers
        bufGroupSize: int
        bufGroupCount: int
    else:
      platform*:   Platform
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
    deadFds:       seq[int]
    fdWatcherPool: seq[FdWatcher]
    running:       bool
    stopFlag:      bool
    bufPool*:      seq[ptr UncheckedArray[byte]]
    occBits:       array[4, array[4, uint64]]  # 256 bits per level for bitmap-accelerated lookup
    nextDead:      int64                       # Earliest timer deadline across all levels
    timerMap:      Table[TimerId, TimerNode]    # TimerId → TimerNode lookup for pause/resume
    pausedList:    seq[TimerNode]               # Timers removed from wheel while paused
    observers:     seq[Observer]                # Variable observers polled each loop
    obsDead:       int
    dns*:          ref RootObj                  # optional DNS resolver context (net/dns)
    sigSource*:    ref RootObj                  # optional OS signal source (signal.nim)
    cleanupCbs:    seq[Callback]                # invoked from close(), for sub-systems
      ## that own loop-thread state (e.g. the DNS resolver) and need to free it
      ## when the loop shuts down.
    closed*:       bool                         # set once close() runs
    postedLock:    Lock                         # guards postedCbs (cross-thread)
    postedCbs:     seq[Callback]                # callbacks posted from other threads
    ownerThread:   int                          # id of the creating thread (-1 w/o threads)
      ## Set to the creating thread's id so higher layers (e.g. WebSocket sends)
      ## can detect calls from other threads and defer them to the loop via
      ## `postToLoop` instead of racing the loop thread's connection state.

# ── Timer wheel helpers ──────────────────────────────────────────────────────

proc monoMs*(): int64 {.inline.} =
  getMonoTime().ticks div 1_000_000

# ── io_uring helpers ─────────────────────────────────────────────────────────

when iouEnabled:
  proc maskOf(events: set[EventType]): int =
    if Read in events:  result = result or uring.POLLIN
    if Write in events: result = result or uring.POLLOUT
    result = result or uring.POLLRDHUP

  proc eventsOf(mask: int): set[EventType] =
    if (mask and uring.POLLIN) != 0:  result.incl Read
    if (mask and uring.POLLOUT) != 0: result.incl Write
    if (mask and uring.POLLERR) != 0: result.incl Error
    if (mask and (uring.POLLHUP or uring.POLLRDHUP)) != 0: result.incl Hup

  proc drainWake(loop: Loop) =
    var val: uint64
    discard posix.read(loop.wakeFd, addr val, 8)

  proc wake*(loop: Loop) {.inline.} =
    var val: uint64 = 1
    discard posix.write(loop.wakeFd, addr val, 8)

# ── io_uring submission helpers ──────────────────────────────────────────────

when iouEnabled:
  proc getOpSqe*(loop: Loop): ptr IoUringSqe {.gcsafe.} =
    ## Claim an SQE slot for a submitted operation (no completion callback yet).
    ## Returns nil when the SQ ring is full.
    loop.ring.getSqe()

  proc commitOp*(loop: Loop, sqe: ptr IoUringSqe, onDone: OpCallback): uint64 {.gcsafe.} =
    ## Assign `user_data` to a claimed SQE and register its completion callback.
    ## `onDone` is stored, never invoked here, so this is GC-safe.
    inc loop.nextToken
    let token = loop.nextToken
    sqe.userData = token
    loop.opCbs[token] = onDone
    result = token

  proc submitOp*(loop: Loop, prep: proc(sqe: ptr IoUringSqe) {.closure.},
                 onDone: OpCallback): uint64 =
    ## Submit an arbitrary operation. `prep` fills the SQE (opcode/fd/addr/len/
    ## opFlags); `user_data` and the completion callback are managed here.
    ## Returns 0 when the SQ ring is full (caller must defer and retry).
    let sqe = loop.ring.getSqe()
    if sqe == nil:
      return 0
    inc loop.nextToken
    let token = loop.nextToken
    prep(sqe)
    sqe.userData = token
    loop.opCbs[token] = onDone
    result = token

  proc cancelOp*(loop: Loop, token: uint64) {.gcsafe.} =
    ## Best-effort cancellation of an in-flight op identified by its token.
    if token == 0: return
    let sqe = loop.ring.getSqe()
    if sqe == nil: return
    inc loop.nextToken
    sqe.opcode = IORING_OP_ASYNC_CANCEL.uint8
    sqe.paddr = token
    sqe.userData = loop.nextToken

  proc armWake(loop: Loop) {.gcsafe.} =
    if loop.wakeArmed: return
    let sqe = loop.ring.getSqe()
    if sqe == nil: return
    sqe.opcode = IORING_OP_POLL_ADD.uint8
    sqe.fd = loop.wakeFd
    sqe.opFlags = uring.POLLIN.uint32
    sqe.userData = loop.wakeToken
    loop.wakeArmed = true

  proc armTimeout(loop: Loop, ms: int) {.gcsafe.} =
    let deadline = monoMs() + ms.int64
    if loop.timeoutPending and loop.timeoutDeadline <= deadline:
      # The armed timeout fires no later than the requested deadline; reusing it
      # avoids a cancel-rearm per poll (each cancel completion wakes enter early
      # and would make the loop spin instead of sleeping).
      return
    if loop.timeoutPending:
      loop.cancelOp(loop.timeoutToken)
      loop.timeoutPending = false
    loop.timeoutTs.tvSec = (ms div 1000).int64
    loop.timeoutTs.tvNsec = ((ms mod 1000) * 1_000_000).int64
    let sqe = loop.ring.getSqe()
    if sqe == nil:
      return
    inc loop.nextToken
    loop.timeoutToken = loop.nextToken
    loop.timeoutDeadline = deadline
    sqe.opcode = IORING_OP_TIMEOUT.uint8
    sqe.paddr = cast[uint64](addr loop.timeoutTs)
    sqe.len = 1
    sqe.opFlags = 0
    sqe.userData = loop.timeoutToken
    loop.timeoutPending = true

  proc flushPending(loop: Loop) =
    ## Re-arm watchers/wake whose one-shot polls completed, then submit all
    ## queued SQEs (ops + re-arms + timeout) without waiting.
    var i = 0
    while i < loop.rearmQueue.len:
      let sqe = loop.ring.getSqe()
      if sqe == nil: break
      let w = loop.rearmQueue[i]
      loop.rearmQueue.del(i)
      if w.alive:
        sqe.opcode = IORING_OP_POLL_ADD.uint8
        sqe.fd = w.fd.cint
        sqe.opFlags = maskOf(w.events).uint32
        sqe.userData = w.token
        w.queued = false
      else:
        loop.watcherTokens.del(w.token)
    loop.armWake()
    discard loop.ring.submit(0, 0)

  proc submitNow*(loop: Loop) {.gcsafe.} =
    ## Submit all queued SQEs to the kernel without waiting. Used by higher
    ## layers (e.g. UDP send) that must guarantee an operation is in flight
    ## before the caller can tear the resource down.
    discard loop.ring.submit(0, 0)

  when defined(powpowBufferSelect):
    proc deferCall*(loop: Loop, cb: Callback) {.inline, gcsafe.}
      ## Forward: defined in the deferred-calls section below.

    proc provideBuffers(loop: Loop, nbufs: int, base: pointer,
                        bufLen: int, bgid: uint16) {.gcsafe.} =
      ## Queue an IORING_OP_PROVIDE_BUFFERS op (one SQE adds `nbufs` contiguous
      ## buffers of `bufLen` bytes to group `bgid`). Submission happens with the
      ## rest of the pending SQEs; if the ring is full the op is deferred.
      let sqe = loop.ring.getSqe()
      if sqe == nil:
        loop.deferCall(proc() =
          loop.provideBuffers(nbufs, base, bufLen, bgid))
        return
      sqe.opcode = IORING_OP_PROVIDE_BUFFERS.uint8
      sqe.fd = nbufs.int32
      sqe.paddr = cast[uint64](base)
      sqe.len = bufLen.uint32
      sqe.setBufGroup(bgid)

    proc bufferSelectEnabled*(loop: Loop): bool {.inline, gcsafe.} =
      ## True when the shared provided-buffer group is active (opt-in via
      ## `-d:powpowBufferSelect` and a kernel that supports multishot recv).
      loop.bufGroup != nil

    proc readBufAt*(loop: Loop, bufId: int): ptr UncheckedArray[byte] {.inline.} =
      ## Address of buffer `bufId` in the shared read group (0-based).
      cast[ptr UncheckedArray[byte]](cast[int](loop.bufGroup) + bufId * loop.bufGroupSize)

    proc recycleReadBuf*(loop: Loop, bufId: int) {.gcsafe.} =
      ## Return a consumed read buffer to the ring so an armed multishot RECV can
      ## select it again. Fire-and-forget: no completion callback is needed.
      loop.provideBuffers(1, cast[pointer](loop.readBufAt(bufId)),
                          DefaultBufSize, ReadBufBgid)

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc newLoop*(entries = 4096): Loop =
  result = Loop(
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
    deadFds:     newSeqOfCap[int](16),
    fdWatcherPool: newSeqOfCap[FdWatcher](16),
    running:     false,
    stopFlag:    false,
    bufPool:     newSeqOfCap[ptr UncheckedArray[byte]](16),
    occBits:     [default array[4, uint64], default array[4, uint64],
                  default array[4, uint64], default array[4, uint64]],
    nextDead:    int64.high,
    timerMap:    initTable[TimerId, TimerNode](),
    pausedList:  newSeqOfCap[TimerNode](16),
    observers:   newSeqOfCap[Observer](16),
    obsDead:     0,
    dns:         nil,
    sigSource:   nil,
    cleanupCbs:  @[],
    closed:      false,
    postedCbs:   @[],
    ownerThread: (when defined(threads): cast[int](getThreadId()) else: -1),
  )
  initLock(result.postedLock)
  when iouEnabled:
    result.ring = initRing(entries)
    result.wakeFd = eventfd(0, EFD_NONBLOCK)
    if result.wakeFd < 0:
      raise newException(OSError, "powpow io_uring: eventfd() failed for wake")
    inc result.nextToken
    result.wakeToken = result.nextToken
    result.armWake()
    discard result.ring.submit(0, 0)
    when defined(powpowBufferSelect):
      if kernelAtLeast(5, 19):
        result.bufGroupSize = DefaultBufSize
        result.bufGroupCount = ReadBufGroupSize
        result.bufGroup = cast[ptr UncheckedArray[byte]](
          allocShared(ReadBufGroupSize * DefaultBufSize))
        result.provideBuffers(ReadBufGroupSize, result.bufGroup,
                              DefaultBufSize, ReadBufBgid)
  else:
    result.platform = Platform.init()

proc addCleanup*(loop: Loop; cb: Callback) =
  ## Register a callback that runs on `loop.close()` (on the same thread that
  ## created the loop). Sub-systems that own loop-thread state — e.g. the DNS
  ## resolver's socket and query table — use this to free themselves.
  loop.cleanupCbs.add(cb)

proc acquireBuf*(loop: Loop): ptr UncheckedArray[byte] {.inline.} =
  if loop.bufPool.len > 0:
    loop.bufPool.pop()
  else:
    cast[ptr UncheckedArray[byte]](allocShared(DefaultBufSize))

proc releaseBuf*(loop: Loop, buf: ptr UncheckedArray[byte]) {.inline.} =
  ## Return a read buffer to the loop's pool, or deallocate it if the loop is
  ## closed (the pool has already been freed) or the pool is full.
  if loop.closed or loop.bufPool.len >= MaxBufPoolSize:
    deallocShared(buf)
  else:
    loop.bufPool.add(buf)

proc close*(loop: Loop) =
  ## Shut the loop down and free its resources. Close servers/connections and
  ## the DNS resolver BEFORE the loop — anything that returns buffers via
  ## `releaseBuf` after this point deallocates them immediately (they cannot be
  ## re-pooled into a freed pool), so buffers handed back post-close are never
  ## leaked. Idempotent.
  if loop.closed: return
  loop.closed = true
  for cb in loop.cleanupCbs:
    cb()
  loop.cleanupCbs.setLen(0)
  loop.dns = nil
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
  when iouEnabled:
    if loop.wakeFd >= 0:
      discard posix.close(loop.wakeFd)
      loop.wakeFd = -1
    when defined(powpowBufferSelect):
      if loop.bufGroup != nil:
        deallocShared(loop.bufGroup)
        loop.bufGroup = nil
    loop.ring.close()
  else:
    loop.platform.close()

# ── Timer wheel ──────────────────────────────────────────────────────────────

proc addToWheel(loop: Loop; node: TimerNode) {.inline.} =
  # Insert `node` into the wheel at the slot for its deadline. This is a pure
  # "put in the wheel" primitive — it does NOT change `totalTimers`, which is
  # managed by the semantic entry/exit points (addTimer/addInterval, the fire
  # loop, pause/resume). Callers that re-add an already-counted node (cascade,
  # interval re-fire) therefore do not double-count.
  let diff = node.deadline - loop.wheelBase
  var level, slot: int
  if diff < 256:
    level = 0
    slot = (node.deadline and 0xFF).int
  elif diff < 65536:
    level = 1
    slot = ((node.deadline shr 8) and 0xFF).int
  elif diff < 16777216:
    level = 2
    slot = ((node.deadline shr 16) and 0xFF).int
  else:
    level = 3
    slot = ((node.deadline shr 24) and 0xFF).int
  node.next = loop.wheel[level][slot]
  loop.wheel[level][slot] = node
  let bitIdx = slot shr 6
  let bitOff = slot and 63
  loop.occBits[level][bitIdx] = loop.occBits[level][bitIdx] or (1.uint64 shl bitOff)
  loop.timerMap[node.id] = node
  if node.deadline < loop.nextDead:
    loop.nextDead = node.deadline

proc cascade(loop: Loop; level: int) {.inline.} =
  let slot = ((loop.wheelBase shr (level * 8)) and 0xFF).int
  var node = loop.wheel[level][slot]
  if node == nil: return
  loop.wheel[level][slot] = nil
  # Bit cleared lazily (dirty tracking): timerTimeout will clean stale bits
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
      when iouEnabled:
        loop.cancelOp(old.token)
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
  when iouEnabled:
    inc loop.nextToken
    watcher.token = loop.nextToken
    loop.watcherTokens[watcher.token] = fd
    # A higher layer may be taking an op-driven connection over with its own
    # readiness watcher; let it cancel its in-flight ops first.
    let takeover = loop.takeoverCbs.getOrDefault(fd)
    if takeover != nil:
      loop.takeoverCbs.del(fd)
      takeover()
    let sqe = loop.ring.getSqe()
    if sqe == nil:
      watcher.queued = true
      loop.rearmQueue.add(watcher)
    else:
      sqe.opcode = IORING_OP_POLL_ADD.uint8
      sqe.fd = fd.cint
      sqe.opFlags = maskOf(events).uint32
      sqe.userData = watcher.token
      watcher.queued = false
  else:
    when not defined(windows):
      # A stale path can register an fd that was already closed and reused (a
      # closed fd is EBADF to kevent/epoll). Tolerate it: leave the watcher
      # dormant instead of raising and killing the whole loop.
      if fcntl(fd.cint, F_GETFD, 0) < 0:
        watcher.alive = false
        return
    loop.platform.add(fd, events, edgeTriggered, cast[pointer](watcher))
    loop.platform.ensureCapacity(loop.fdWatchers.len)

proc unregister*(loop: Loop, fd: int) =
  if fd in loop.fdWatchers:
    let w = loop.fdWatchers[fd]
    if not w.alive: return
    w.alive = false
    inc loop.deadCount
    loop.fdWatcherPool.add(w)
    when iouEnabled:
      loop.cancelOp(w.token)
    else:
      loop.platform.remove(fd)

proc unregisterFd*(loop: Loop, fd: int) =
  ## Remove fd watcher. On POSIX the fd is already closed by the caller and
  ## the OS removes it from epoll/kqueue automatically, so only in-memory
  ## state is cleaned. On Windows/IOCP the per-fd state must be explicitly
  ## removed — deferred-free handles late completions from closesocket.
  if fd in loop.fdWatchers:
    let w = loop.fdWatchers[fd]
    w.alive = false
    inc loop.deadCount
    loop.fdWatcherPool.add(w)
    loop.fdWatchers.del(fd)
    when iouEnabled:
      loop.watcherTokens.del(w.token)
      loop.cancelOp(w.token)
    else:
      when defined(windows):
        loop.platform.remove(fd)

proc modify*(loop: Loop, fd: int, events: set[EventType]) {.inline.} =
  when iouEnabled:
    if fd in loop.fdWatchers:
      let w = loop.fdWatchers[fd]
      if w.alive:
        w.events = events
        loop.cancelOp(w.token)
        if not w.queued:
          w.queued = true
          loop.rearmQueue.add(w)
    elif Write in events and loop.writabilityHooks.len > 0:
      # Op-driven connections (io/tcp) don't use fd watchers, but higher layers
      # (e.g. the HTTP server's zero-copy sendfile) still signal "watch for
      # writability" via `modify(fd, {Read, Write})`. Arm a one-shot POLL_ADD
      # Write poll and notify the registered hooks when the socket drains.
      let sqe = loop.ring.getSqe()
      if sqe != nil:
        inc loop.nextToken
        let token = loop.nextToken
        loop.writabilityTokens[token] = fd
        sqe.opcode = IORING_OP_POLL_ADD.uint8
        sqe.fd = fd.cint
        sqe.opFlags = uring.POLLOUT.uint32
        sqe.userData = token
  else:
    if fd in loop.fdWatchers:
      let w = loop.fdWatchers[fd]
      if w.alive:
        w.events = events
        loop.platform.modify(fd, events, w.edgeTriggered, cast[pointer](w))

when iouEnabled:
  proc addWritabilityHook*(loop: Loop, cb: proc(fd: int) {.closure.}) {.gcsafe.} =
    loop.writabilityHooks.add(cb)

  proc setTakeoverCb*(loop: Loop, fd: int, cb: proc() {.closure.}) {.gcsafe.} =
    ## Register a callback for an op-driven connection's fd: when a watcher is
    ## later registered for that fd (a higher layer taking the connection over),
    ## the callback runs so the TCP layer can cancel its in-flight RECV.
    loop.takeoverCbs[fd] = cb

  proc clearTakeoverCb*(loop: Loop, fd: int) {.gcsafe.} =
    loop.takeoverCbs.del(fd)

  proc isWatched*(loop: Loop, fd: int): bool {.inline, gcsafe.} =
    loop.fdWatchers.hasKey(fd)

# ── deferred calls ──────────────────────────────────────────────────────────

proc deferCall*(loop: Loop, cb: Callback) {.inline, gcsafe.} =
  loop.deferred.addLast(cb)

proc postToLoop*(loop: Loop, cb: Callback) =
  ## Thread-safe: run `cb` on the loop's thread at the next poll iteration.
  ## Used to hand work from other threads (e.g. the Windows Ctrl+C handler) to
  ## the loop thread. Requires `--threads:on` for real cross-thread safety.
  withLock(loop.postedLock):
    loop.postedCbs.add(cb)
  when iouEnabled:
    loop.wake()
  else:
    loop.platform.wake()

# ── timers ───────────────────────────────────────────────────────────────────

proc addTimer*(loop: Loop, delayMs: int, callback: TimerCallback): TimerId =
  inc loop.nextTimerId
  result = TimerId(loop.nextTimerId)
  let node = TimerNode(
    id:       result,
    deadline: monoMs() + delayMs.int64,
    interval: 0,
    delayMs:  delayMs.int64,
    callback: callback,
    cancelled: false,
    paused:   false,
  )
  inc loop.totalTimers
  addToWheel(loop, node)

proc addInterval*(loop: Loop, intervalMs: int,
                  callback: TimerCallback): TimerId =
  inc loop.nextTimerId
  result = TimerId(loop.nextTimerId)
  let node = TimerNode(
    id:       result,
    deadline: monoMs() + intervalMs.int64,
    interval: intervalMs.int64,
    delayMs:  intervalMs.int64,
    callback: callback,
    cancelled: false,
    paused:   false,
  )
  inc loop.totalTimers
  addToWheel(loop, node)

proc cancelTimer*(loop: Loop; id: TimerId) =
  ## Cancel a timer. A timer still in the wheel is flagged for lazy removal
  ## when it reaches the front of the wheel (so no wheel surgery is needed).
  ## A timer already paused (moved out of the wheel) is dropped immediately —
  ## it was already removed from `totalTimers` when it was paused.
  for i in 0 ..< loop.pausedList.len:
    if loop.pausedList[i].id == id:
      loop.pausedList.del(i)
      loop.timerMap.del(id)
      return
  loop.cancelled.incl(id)

proc pauseTimer*(loop: Loop; id: TimerId) =
  ## Pause a timer at its next scheduled fire.
  ## The timer is lazily removed from the wheel during processTimers
  ## and stored in a paused list. When resumed, it is re-scheduled
  ## from the current time (paused duration is not compensated).
  let node = loop.timerMap.getOrDefault(id)
  if node != nil:
    node.paused = true

proc resumeTimer*(loop: Loop; id: TimerId) =
  ## Resume a previously paused timer. The timer fires after its
  ## original delay/interval from the moment of resume.
  for i in 0 ..< loop.pausedList.len:
    if loop.pausedList[i].id == id:
      let node = loop.pausedList[i]
      loop.pausedList.del(i)
      node.paused = false
      node.deadline = monoMs() + (if node.interval > 0: node.interval else: node.delayMs)
      inc loop.totalTimers   # re-enter the wheel: was decremented when paused
      addToWheel(loop, node)
      return
  # Not yet in pausedList — still in the wheel with paused=true
  let node = loop.timerMap.getOrDefault(id)
  if node != nil:
    node.paused = false

proc timerCount*(loop: Loop): int {.inline.} =
  ## Number of timers currently in the wheel (not paused, not cancelled-pending).
  ## 0 means the loop can skip timer processing entirely. Exposed for
  ## observability/tests.
  loop.totalTimers

# ── idle handlers ────────────────────────────────────────────────────────────

proc addIdle*(loop: Loop, cb: Callback): int {.inline.} =
  inc loop.nextIdleId
  result = loop.nextIdleId
  loop.idleCbs[result] = cb

proc removeIdle*(loop: Loop, id: int) {.inline.} =
  loop.idleCbs.del(id)

# ── observers ─────────────────────────────────────────────────────────────────

proc observe*(loop: Loop; varPtr: ptr uint64; cb: ObserverCallback): Observer =
  ## Observe a variable at `varPtr`. The callback is invoked on each poll
  ## iteration when the variable's value changes from the last observed value.
  ## Returns an Observer handle that can be passed to `cancelObserver`.
  result = Observer(varPtr: varPtr, lastVal: varPtr[], cb: cb, alive: true)
  loop.observers.add(result)

proc cancelObserver*(obs: Observer) =
  ## Cancel an observer. The observer is lazily removed from the loop
  ## during the next sweep.
  obs.alive = false

# ── control ──────────────────────────────────────────────────────────────────

proc stop*(loop: Loop) =
  loop.stopFlag = true
  when iouEnabled:
    loop.wake()
  else:
    loop.platform.wake()

proc isRunning*(loop: Loop): bool =
  loop.running

# ── internal: process timers ─────────────────────────────────────────────────

proc processTimers(loop: Loop; now: int64) =
  if loop.totalTimers == 0:
    loop.wheelBase = now
    return
  # Advance wheelBase to now, cascading at level-1 boundaries (every 256ms).
  # Jump directly to each boundary instead of stepping 1ms at a time,
  # reducing O(idle_gap) to O(idle_gap / 256) iterations.
  # Update wheelBase before cascade so the slot computation uses the correct
  # boundary time (fixes stale-wheelBase cascade bug).
  var t = loop.wheelBase
  while t < now:
    let toBoundary = 256 - (t and 0xFF)
    if t + toBoundary <= now:
      t += toBoundary
      loop.wheelBase = t
      cascade(loop, 1)
      if (t and 0xFFFF) == 0:
        cascade(loop, 2)
      if (t and 0xFFFFFF) == 0:
        cascade(loop, 3)
    else:
      t = now
  loop.wheelBase = now

  # Fire all expired Level-0 timers up to batch limit.
  var batch = 0
  for slot in 0 ..< 256:
    if batch >= MaxTimerBatch:
      break
    var prev: TimerNode = nil
    var node = loop.wheel[0][slot]
    while node != nil and batch < MaxTimerBatch:
      let next = node.next
      if node.deadline <= now:
        if prev == nil:
          loop.wheel[0][slot] = next
        else:
          prev.next = next
        node.next = nil
        inc batch
        if node.paused:
          loop.pausedList.add(node)
          dec loop.totalTimers
        elif node.id in loop.cancelled:
          loop.cancelled.excl(node.id)
          dec loop.totalTimers
          loop.timerMap.del(node.id)
        else:
          node.callback(node.id.int)
          if node.interval > 0:
            node.deadline = now + node.interval
            addToWheel(loop, node)
          else:
            dec loop.totalTimers
            loop.timerMap.del(node.id)
      else:
        prev = node
      node = next

  # Prune cancelled ids whose timer has already been resolved (no longer in the
  # wheel or paused list) so the set stays bounded. Never drop an id for a
  # still-pending timer — that would let its callback fire after cancellation.
  if loop.cancelled.len > loop.totalTimers * 2 + 16:
    var stale: seq[TimerId]
    for id in loop.cancelled:
      if id notin loop.timerMap:
        stale.add(id)
    for id in stale:
      loop.cancelled.excl(id)
  loop.nextDead = int64.high

proc timerTimeout(loop: Loop; now: int64): int =
  if loop.totalTimers == 0:
    return -1
  if loop.wheelBase < now:
    return 0

  # Skip-ahead: only use cached nextDead when it hasn't been invalidated
  if loop.nextDead != int64.high and now < loop.nextDead:
    let wait = loop.nextDead - now
    if wait > int64(high(int)):
      return high(int)
    return wait.int

  # Bitmap-accelerated scan with lazy dirty-bit cleanup.
  # Stale bits (set but slot empty after fire/cascade) are cleared on discovery.
  var earliest = int64.high
  for level in 0 ..< 4:
    if earliest != int64.high: break
    for i in 0 ..< 4:
      var bits = loop.occBits[level][i]
      while bits != 0:
        let bitPos = countTrailingZeroBits(bits)
        let mask = 1.uint64 shl bitPos
        bits = bits and not mask
        let slot = i * 64 + bitPos
        var node = loop.wheel[level][slot]
        if node == nil:
          loop.occBits[level][i] = loop.occBits[level][i] and not mask
        else:
          while node != nil:
            if node.deadline < earliest:
              earliest = node.deadline
            node = node.next

  if earliest == int64.high:
    return -1
  loop.nextDead = earliest
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

proc drainPosted(loop: Loop) {.inline.} =
  ## Run callbacks posted from other threads (postToLoop).
  if loop.postedCbs.len > 0:
    var batch: seq[Callback]
    withLock(loop.postedLock):
      batch = loop.postedCbs
      loop.postedCbs.setLen(0)
    for cb in batch:
      cb()

# ── internal: sweep dead watchers ────────────────────────────────────────────

proc sweepDead(loop: Loop) {.inline.} =
  if loop.deadCount > 64:
    loop.deadFds.setLen(0)
    for fd, w in loop.fdWatchers:
      if not w.alive:
        loop.deadFds.add(fd)
    for fd in loop.deadFds:
      loop.fdWatchers.del(fd)
    loop.deadCount = 0

when iouEnabled:
  proc dispatchWatcher(loop: Loop, fd: int, token: uint64, res: int32) =
    let w = loop.fdWatchers.getOrDefault(fd)
    if w == nil or not w.alive or w.token != token:
      return
    if res >= 0:
      let events = eventsOf(res)
      if events != {}:
        w.callback(fd, events)
    if w.alive and not w.queued:
      w.queued = true
      loop.rearmQueue.add(w)

  proc reap(loop: Loop) =
    loop.reaped = 0
    while true:
      let cqe = loop.ring.peekCqe()
      if cqe == nil: break
      let ud = cqe.userData
      let res = cqe.res
      let fl = cqe.flags
      loop.ring.advanceCq()
      if ud == loop.wakeToken:
        loop.wakeArmed = false
        loop.drainWake()
      elif ud == loop.timeoutToken:
        loop.timeoutPending = false
      else:
        let fd = loop.watcherTokens.getOrDefault(ud, -1)
        if fd != -1:
          loop.dispatchWatcher(fd, ud, res)
          inc loop.reaped
        else:
          let wfd = loop.writabilityTokens.getOrDefault(ud, -1)
          if wfd != -1:
            loop.writabilityTokens.del(ud)
            if res >= 0:
              for cb in loop.writabilityHooks:
                cb(wfd)
          else:
            let cb = loop.opCbs.getOrDefault(ud)
            if cb != nil:
              if (fl and IORING_CQE_F_MORE) == 0:
                # One-shot completion: no further CQEs for this token. For
                # multishot ops (F_MORE) the callback stays registered so
                # subsequent completions of the same SQE still dispatch.
                loop.opCbs.del(ud)
              cb(res, fl)
              inc loop.reaped

# ── main loop ────────────────────────────────────────────────────────────────

proc poll*(loop: Loop, timeoutMs: int = -1) {.inline.} =
  let now = monoMs()

  processDeferred(loop)
  drainPosted(loop)
  if loop.stopFlag: return

  processTimers(loop, now)
  if loop.stopFlag: return

  var timeout = timeoutMs
  if timeout < 0:
    timeout = timerTimeout(loop, now)

  var nEvents = 0
  when iouEnabled:
    flushPending(loop)
    var minComplete: cuint = 0
    if timeout >= 0:
      if timeout > 0:
        armTimeout(loop, timeout)
        minComplete = 1
    else:
      minComplete = 1
    # Single enter per poll: submits every queued SQE (re-arms, ops queued by
    # callbacks last iteration, the timeout) and blocks for a completion.
    var ret = loop.ring.submit(minComplete, IORING_ENTER_GETEVENTS)
    while ret == -EINTR:
      ret = loop.ring.submit(minComplete, IORING_ENTER_GETEVENTS)
    if ret < 0:
      loop.reaped = 0
    loop.reap()
    nEvents = loop.reaped
    flushPending(loop)
  else:
    nEvents = loop.platform.poll(timeout)
    for i in 0 ..< nEvents:
      let pev = loop.platform.events[i]
      let w = cast[FdWatcher](pev.udata)
      # Stale-event guard: the watcher pointer in this event must still be the
      # CURRENT registration for its fd. A watcher that was unregistered and
      # pooled (then possibly reused for another fd/registration) must not be
      # dispatched — this is the generation-counter check.
      if w != nil and w.alive and loop.fdWatchers.getOrDefault(w.fd) == w:
        w.callback(w.fd, pev.events)
  if loop.stopFlag: return

  if loop.totalTimers > 0:
    # Timers may have expired during the I/O wait — recompute and fire them.
    let now2 = monoMs()
    processTimers(loop, now2)
  if loop.stopFlag: return

  sweepDead(loop)  # Check observers for variable changes
  for obs in loop.observers.mitems:
    if obs.alive:
      let val = obs.varPtr[]
      if val != obs.lastVal:
        obs.lastVal = val
        obs.cb(val)
    else:
      inc loop.obsDead
  if loop.obsDead > 64:
    loop.observers.keepItIf(it.alive)
    loop.obsDead = 0

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
