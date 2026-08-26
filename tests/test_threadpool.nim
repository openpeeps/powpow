## ThreadPool tests: parallel execution, FIFO result ordering, exception
## reporting, graceful drain close, immediate discard shutdown, and hosting
## timers on the pool's private loop.
##
## Callbacks fire on the pool's own dispatch thread, so the test main thread
## synchronizes through lock-guarded counters (no external loop needed).
## Compile/run with `--threads:on` (the `test` nimble task always uses it).

import std/[locks, os, times, unittest]
import ../src/powpow

# ── Shared test helpers ──────────────────────────────────────────────────────

type
  Guard = object
    lock: Lock
    count: int
    items: seq[int]
    lastError: string
    errorFired: bool

proc init(g: var Guard) =
  initLock(g.lock)

proc bump(g: ptr Guard) =
  withLock(g.lock):
    inc g.count

proc waitFor(g: ptr Guard, target: int, timeoutMs = 10_000): bool =
  ## Poll until `count >= target` or the deadline passes.
  let deadline = now() + milliseconds(timeoutMs)
  while now() < deadline:
    withLock(g.lock):
      if g.count >= target:
        return true
    sleep(5)
  false

suite "threadpool":

  test "parallel_jobs_run_concurrently":
    # 8 jobs x ~80ms of blocking work on 4 workers must beat serial time.
    var g: Guard
    init(g)
    let tp = newThreadPool(size = 4)

    var t0 = now()
    for i in 0 ..< 8:
      discard tp.submitWork(
        job = proc(): int {.closure.} =
          {.cast(gcsafe).}:
            sleep(80)
          i,
        cb = proc(res: int) {.closure.} =
          {.cast(gcsafe).}:
            bump(addr g))
    check waitFor(addr g, 8)
    let elapsedMs = (now() - t0).inMilliseconds

    check elapsedMs < 8 * 80   # strictly better than fully-serial
    # Makespan floor: 8 blocking jobs / max 4 concurrent => >= 2 rounds.
    check elapsedMs >= 140
    closeThreadPool(tp)

  test "fifo_ordering_single_worker":
    # One worker => completion order == submission order.
    var g: Guard
    init(g)
    let tp = newThreadPool(size = 1)
    const N = 50

    # Build jobs through a factory: closure parameters get a fresh
    # environment per call, while per-iteration `let` bindings can be lifted
    # into ONE shared slot by Nim's closure lifting (all jobs would observe
    # the final counter value).
    proc makeJob(v: int): proc (): int {.closure.} =
      result = proc (): int = v

    for i in 0 ..< N:
      discard tp.submitWork(
        job = makeJob(i),
        cb = proc(res: int) {.closure.} =
          {.cast(gcsafe).}:
            withLock(g.lock):
              g.items.add(res)
              inc g.count)
    check waitFor(addr g, N)

    withLock(g.lock):
      check g.items.len == N
      for i in 0 ..< N:
        check g.items[i] == i
    closeThreadPool(tp)

  test "stress_all_delivered_exactly_once":
    var g: Guard
    init(g)
    let tp = newThreadPool(size = 4)
    const N = 2000

    for i in 0 ..< N:
      discard tp.submitWork(
        job = proc(): int {.closure.} = i * 2,
        cb = proc(res: int) {.closure.} =
          {.cast(gcsafe).}:
            bump(addr g))
    check waitFor(addr g, N, timeoutMs = 30_000)
    withLock(g.lock):
      check g.count == N
    closeThreadPool(tp)

  test "raising_job_reports_error_pool_survives":
    var g: Guard
    init(g)
    let tp = newThreadPool(size = 2)

    proc onDone(res: string) {.closure.} =
      {.cast(gcsafe).}:
        withLock(g.lock):
          inc g.count

    proc onFail(err: ref CatchableError) {.closure.} =
      {.cast(gcsafe).}:
        withLock(g.lock):
          g.errorFired = true
          g.lastError = err.msg

    discard tp.submitWork(
      job = proc(): string {.closure.} =
        raise newException(ValueError, "boom"),
      cb = onDone,
      onError = onFail)

    # onError must fire and cb must not.
    let deadline = now() + milliseconds(5000)
    while now() < deadline:
      withLock(g.lock):
        if g.errorFired: break
      sleep(5)
    withLock(g.lock):
      check g.errorFired
      check g.lastError == "boom"
      check g.count == 0

    # Pool remains usable after a raising job.
    discard tp.submitWork(
      job = proc(): int {.closure.} = 41 + 1,
      cb = proc(res: int) {.closure.} =
        {.cast(gcsafe).}:
          bump(addr g))
    check waitFor(addr g, 1)
    closeThreadPool(tp)

  test "close_drains_pending_jobs":
    # Graceful close blocks until every queued job ran and delivered.
    var g: Guard
    init(g)
    let tp = newThreadPool(size = 2)
    const N = 30

    for i in 0 ..< N:
      discard tp.submitWork(
        job = proc(): int {.closure.} =
          {.cast(gcsafe).}:
            sleep(5)
          i,
        cb = proc(res: int) {.closure.} =
          {.cast(gcsafe).}:
            bump(addr g))

    closeThreadPool(tp)     # returns only after full drain + teardown
    withLock(g.lock):
      check g.count == N

  test "shutdown_discards_queued_keeps_inflight":
    # A gate-held job occupies the only worker; 20 more queue up behind it.
    # A helper thread releases the gate while the main thread is already inside
    # shutdownThreadPool: the queued jobs must be discarded, the in-flight job
    # must finish and deliver, and shutdown must return promptly afterwards.
    var g: Guard
    var gate: Cond
    var release = false
    init(g)
    initCond(gate)

    type GateCtx = object
      lk: ptr Lock
      cond: ptr Cond
      flag: ptr bool
    var gctx: GateCtx

    proc releaserMain(arg: pointer) {.thread.} =
      {.cast(gcsafe).}:
        let c = cast[ptr GateCtx](arg)
        os.sleep(120)
        # Signal UNDER the lock: signaling outside would race the waiter's
        # predicate-check -> wait window (lost wakeup).
        withLock(c.lk[]):
          c.flag[] = true
          c.cond[].signal()

    let tp = newThreadPool(size = 1)
    const Queued = 20

    discard tp.submitWork(
      job = proc(): int {.closure.} =
        {.cast(gcsafe).}:
          while true:
            withLock(g.lock):
              if release: break
              gate.wait(g.lock)
          7,
      cb = proc(res: int) {.closure.} =
        {.cast(gcsafe).}:
          doAssert res == 7
          bump(addr g))

    for i in 0 ..< Queued:
      discard tp.submitWork(
        job = proc(): int {.closure.} = i,
        cb = proc(res: int) {.closure.} =
          {.cast(gcsafe).}:
            withLock(g.lock):
              inc g.count           # queued jobs must NEVER deliver
              g.items.add(res))

    sleep(80)                     # let the queue fill up behind the gate job
    gctx = GateCtx(lk: addr g.lock, cond: addr gate, flag: addr release)
    var rel: Thread[pointer]
    createThread(rel, releaserMain, addr gctx)

    let t0 = now()
    shutdownThreadPool(tp)        # discards the 20 queued once the worker frees up
    let shutdownMs = (now() - t0).inMilliseconds
    joinThread(rel)

    check shutdownMs < 5000       # bounded by the releaser, not the queue
    withLock(g.lock):
      check g.count == 1          # exactly the in-flight job delivered
      check g.items.len == 0      # queued callbacks never fired

    deinitCond(gate)

  test "submit_after_close_rejected":
    var g: Guard
    init(g)

    block graceful:
      let tp = newThreadPool(size = 2)
      discard tp.submitWork(
        job = proc(): int {.closure.} = 1,
        cb = proc(res: int) {.closure.} =
          {.cast(gcsafe).}:
            bump(addr g))
      check waitFor(addr g, 1)
      closeThreadPool(tp)
      let accepted = tp.submitWork(
        job = proc(): int {.closure.} = 2,
        cb = proc(res: int) {.closure.} = discard)
      check accepted == false

    block immediate:
      let tp = newThreadPool(size = 2)
      shutdownThreadPool(tp)
      let accepted = tp.submitWork(
        job = proc(): int {.closure.} = 3,
        cb = proc(res: int) {.closure.} = discard)
      check accepted == false

  test "get_loop_hosts_timers":
    # The pool's private loop is live and hostable (HttpClient.getLoop style).
    # Hosting rule: register FROM the dispatch thread — i.e. from inside a
    # result callback — so the timer callback is created and destroyed on the
    # thread that runs it.
    var g: Guard
    init(g)
    let tp = newThreadPool(size = 2)

    discard tp.submitWork(
      job = proc(): int {.closure.} = 0,
      cb = proc(res: int) {.closure.} =
        {.cast(gcsafe).}:
          let loop = tp.getLoop()
          discard loop.addTimer(25) do (id: int):
            {.cast(gcsafe).}:
              bump(addr g))
    check waitFor(addr g, 1)

    closeThreadPool(tp)
