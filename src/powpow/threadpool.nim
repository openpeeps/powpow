# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## Self-managed thread pool built on raw threads, condvars and powpow's own
## event loop — no high-level parallelism APIs.
##
## A `ThreadPool` owns everything it needs: N persistent worker threads fed by
## an unbounded FIFO job queue (Lock + Cond), plus one dedicated dispatch
## thread running the pool's *private* event loop. Job results are delivered
## on that loop, serialized against the other completions.
##
##   ```nim
##   let tp = newThreadPool(size = 4)
##
##   # cb runs on tp's dispatch thread once a worker finished the job:
##   discard tp.submitWork(
##     job = proc(): string {.closure.} = heavyComputation(),
##     cb  = proc(res: string) {.closure.} =
##       echo "got ", res.len, " bytes"
##   )
##
##   closeThreadPool(tp)      # graceful: drain queued jobs, then tear down
##   ```
##
## Because callbacks run on the pool's dispatch thread — concurrent with the
## caller's thread — any state they touch must be synchronized (lock-guarded
## counters, queues, …). Use `getLoop` to host extra timers or sockets on the
## pool's loop.
##
## Shutdown comes in two flavors:
## - `closeThreadPool` stops accepting work, lets workers drain the queue
##   (all results still delivered), joins everything.
## - `shutdownThreadPool` stops accepting work and DISCARDS jobs that were
##   queued but never started (their callbacks never fire); in-flight jobs
##   finish naturally and deliver.
##
## ## Memory-management notes (why the plumbing looks the way it does)
##
## Under ARC/ORC, reference-count operations are NOT atomic: a managed cell
## must have exactly one owning thread at any instant, and its final release
## must happen on whichever thread currently owns it — never concurrently
## from two threads. Posting closures across threads (e.g. `postToLoop` while
## the producer keeps an owning local) makes the *release thread*
## scheduler-dependent, which corrupts ORC's per-thread cycle registry
## (`rememberCycle`/`unregisterCycle` SIGSEGV). This module therefore follows
## strict single-owner move semantics for everything crossing a boundary:
##
## - Workers never touch shared managed state: they operate solely on an
##   unmanaged `PoolCore` (locks, condvar, intrusive queues, counters).
## - Each task's job/cb/onError closures live in a managed `TaskBox` whose
##   single reference count travels submitter -> worker -> dispatcher via raw
##   pointers plus `wasMoved` — exactly one owner at every instant, finally
##   released on the dispatch thread (the thread that also runs every
##   callback for the pool's lifetime).
## - Completion wake-up uses `loop.observe` on an atomic tick counter instead
##   of posting closures from workers. The observer closure is created once,
##   lives entirely on the dispatch thread and dies on the thread that
##   created it (during teardown).
##
## Compile with threads enabled (`--threads:on`; recent Nim compilers enable
## them by default). Builds that must avoid threads entirely can pass
## `-d:powpowNoThreads`: the module then compiles but every entry point raises
## `ThreadPoolError`.

when not defined(powpowNoThreads):
  import ./types
  import ./loop
  import std/[atomics, locks]

  export types

  const
    HeartbeatMs* = 10
      ## Dispatch-loop keep-alive cadence. Also bounds worst-case result
      ## delivery latency when no other loop activity forces poll iterations.

  type
    ThreadPoolError* = object of CatchableError

    Trampoline = proc (node: ptr TaskNode) {.cdecl, gcsafe.}
      ## Plain function pointer (no environment), instantiated per result type
      ## T. Drives a task box through its two phases: run (worker side) and
      ## deliver (dispatch side).

    TaskNode = object
      ## Unmanaged intrusive queue cell. `box` is the raw handle to the task's
      ## managed payload; ownership of that handle moves together with the
      ## node itself.
      tramp: Trampoline
      box: pointer
      core: ptr PoolCore       ## Set on work-phase nodes; used to publish results
      next: ptr TaskNode

    PoolCore = object
      ## Everything workers touch — deliberately free of managed fields so no
      ## reference-count operation can race between threads.
      lock: Lock
      space: Cond              ## Signalled on new work and on state changes
      workHead: ptr TaskNode   ## Pending jobs (submitter -> worker), FIFO
      workTail: ptr TaskNode
      doneHead: ptr TaskNode   ## Completed results (worker -> dispatch), FIFO
      doneTail: ptr TaskNode
      doneTick: Atomic[uint64] ## Bumped per published result; wakes the observer.
        ## The observer watches the raw storage (`Atomic[T]` is a wrapper over
        ## a single suitably-aligned value); `fetchAdd` provides release
        ## ordering for the list pointers published before it.
      closing: bool            ## Graceful stop requested: drain, then exit
      dead: bool               ## Immediate stop requested: discard queued jobs
      tearingDown: bool        ## Teardown started (idempotence guard)
      workersJoined: bool      ## All workers joined; observer may stop the loop

    ThreadPool* = ref object
      ## Self-managed worker pool: N workers plus one dispatch thread running
      ## a private event loop. Every result callback fires on that dispatch
      ## thread. After `closeThreadPool`/`shutdownThreadPool` the pool is
      ## spent: `submitWork` returns false and `getLoop` must not be used.
      loop: Loop
      core: ptr PoolCore       ## Unmanaged shared state; nil after teardown
      size: int
      workers: seq[Thread[ptr PoolCore]]
      dispatcher: Thread[ptr DispArg]
      loopHandle: pointer      ## Owning raw handle to `loop` (see teardown)
      darg: ptr DispArg        ## Dispatch launch args; freed after join

    DispArg = object
      ## Unmanaged launch arguments for the dispatch thread.
      core: ptr PoolCore
      loopRaw: pointer         ## Borrowing view of the shell's loop

  # ── Managed task payload ──────────────────────────────────────────────────
  #
  # A `Box[T]` has exactly one owning thread during its whole life:
  #   submitter (until enqueue) -> worker (while running) -> dispatcher (which
  # delivers and lets it die there). Transfers move the raw handle and use
  # `wasMoved` so no thread ever decrements a cell another thread may touch.

  type
    BoxBase = object of RootObj
      failed: bool

    Box[T] = ref object of BoxBase
      job: proc (): T {.closure.}
      cb: proc (res: T) {.closure.}
      onErrorCb: proc (err: ref CatchableError) {.closure.}
      res: T
      err: ref CatchableError

  # ── Queue helpers ─────────────────────────────────────────────────────────

  proc newNode(tramp: Trampoline, box: pointer,
               core: ptr PoolCore): ptr TaskNode =
    result = cast[ptr TaskNode](allocShared0(sizeof(TaskNode)))
    result.tramp = tramp
    result.box = box
    result.core = core

  proc freeNode(n: ptr TaskNode) {.inline.} =
    deallocShared(n)

  proc pushWork(core: ptr PoolCore, n: ptr TaskNode) =
    ## Append to the pending-jobs FIFO. Caller holds `core.lock`.
    n.next = nil
    if core.workTail == nil:
      core.workHead = n
      core.workTail = n
    else:
      core.workTail.next = n
      core.workTail = n

  proc popWork(core: ptr PoolCore): ptr TaskNode =
    ## Take the oldest pending job or nil. Caller holds `core.lock`.
    result = core.workHead
    if result != nil:
      core.workHead = result.next
      if core.workHead == nil:
        core.workTail = nil
      result.next = nil

  proc pushDone(core: ptr PoolCore, n: ptr TaskNode) =
    ## Append to the completed-results FIFO. Caller holds `core.lock`.
    n.next = nil
    if core.doneTail == nil:
      core.doneHead = n
      core.doneTail = n
    else:
      core.doneTail.next = n
      core.doneTail = n

  proc popDone(core: ptr PoolCore): ptr TaskNode =
    ## Take the oldest completed result or nil. Caller holds `core.lock`.
    result = core.doneHead
    if result != nil:
      core.doneHead = result.next
      if core.doneHead == nil:
        core.doneTail = nil
      result.next = nil

  # ── Trampolines (per result type T) ───────────────────────────────────────

  proc deliverTask[T](node: ptr TaskNode) {.cdecl, gcsafe.}
    ## Forward declaration: runTask publishes results through it.

  proc runTask[T](node: ptr TaskNode) {.cdecl, gcsafe.} =
    ## Worker phase: take sole ownership of the box, run the job, publish the
    ## outcome to the done queue, hand ownership to the dispatcher.
    let core = node.core
    var b = cast[Box[T]](node.box)
    node.box = nil
    try:
      {.cast(gcsafe).}:
        b.res = b.job()
    except CatchableError as e:
      b.failed = true
      b.err = e

    let doneNode = newNode(deliverTask[T], cast[pointer](b), core)
    withLock(core.lock):
      pushDone(core, doneNode)
    # Publish before waking the observer.
    discard core.doneTick.fetchAdd(1, moRelease)
    wasMoved(b)
    freeNode(node)

  proc deliverTask[T](node: ptr TaskNode) {.cdecl, gcsafe.} =
    ## Dispatch phase (runs on the dispatch thread): sole owner of the box;
    ## invoke the user callback; the scope-end release frees the box HERE.
    var b = cast[Box[T]](node.box)
    node.box = nil
    {.cast(gcsafe).}:
      # User callbacks are unguarded, consistent with every other powpow
      # callback surface: a raising cb tears down the process like anywhere
      # else in the library.
      if b.failed:
        if b.onErrorCb != nil:
          b.onErrorCb(b.err)
        # else: failure swallowed; pool stays healthy
      else:
        b.cb(b.res)
    # `b` dies here — final release on the dispatch thread, single owner.
    freeNode(node)

  # ── Result draining (dispatch thread only) ────────────────────────────────

  proc drainDone(core: ptr PoolCore) {.gcsafe.} =
    ## Run every pending result callback. Called exclusively from the
    ## observer, i.e. serialized onto the dispatch thread.
    while true:
      var node: ptr TaskNode
      withLock(core.lock):
        node = popDone(core)
      if node == nil:
        return
      {.cast(gcsafe).}:
        node.tramp(node)

  # ── Thread bodies ─────────────────────────────────────────────────────────

  proc workerMain(arg: ptr PoolCore) {.thread.} =
    ## Pop tasks FIFO-style and run them outside the lock. Exits when `dead`
    ## is set (queued jobs discarded, their boxes released here) or when
    ## `closing` is set and the queue ran dry.
    ##
    ## This body performs no managed allocation of its own: task boxes arrive
    ## as raw handles with ownership transferred in, and leave the same way.
    let core = arg
    var running = true
    while running:
      var item: ptr TaskNode
      block dequeue:
        withLock(core.lock):
          while core.workHead == nil and not core.closing and not core.dead:
            core.space.wait(core.lock)
          if core.dead:
            # Discard every queued job: release each box on THIS thread
            # (we are its current owner) so closures cannot leak.
            while true:
              let dropped = popWork(core)
              if dropped == nil: break
              var junk {.used.} = cast[BoxBase](dropped.box)   # typed view, sole owner
              dropped.box = nil                       # scope-end release below
              freeNode(dropped)
            running = false
          elif core.workHead != nil:
            item = popWork(core)
          else:
            running = false                           # closing && drained
      if item != nil:
        {.cast(gcsafe).}:
          item.tramp(item)
        # `item.box` moved on to the done queue inside the trampoline.

  proc dispatcherMain(arg: ptr DispArg) {.thread.} =
    ## Drive the pool's private loop. Results are delivered by the tick
    ## observer registered in `newThreadPool`; the teardown sentinel posted
    ## after the workers join makes this proc return.
    var lp = cast[Loop](arg.loopRaw)   # borrowing view; creator outlives us
    {.cast(gcsafe).}:
      # A loop carrying only observers would block inside the platform wait
      # forever (no fds, no timers => no wakeups), so the observer sweep would
      # never run. A small repeating timer guarantees poll iterations; it also
      # bounds worst-case delivery latency. Registered HERE (dispatch thread)
      # so the interval closure lives and dies on the thread that runs it.
      discard lp.addInterval(HeartbeatMs) do (id: int):
        discard
      lp.run()
    wasMoved(lp)   # borrowed, not owned: no reference-count op on exit

  # ── Lifecycle ─────────────────────────────────────────────────────────────

  proc newThreadPool*(size: int = 4): ThreadPool =
    ## Create a pool with `size` persistent workers plus one dispatch thread
    ## running the pool's private event loop. Returns immediately; workers
    ## idle-wait on the condition variable until the first job arrives.
    if size < 1:
      raise newException(ThreadPoolError, "size must be >= 1")
    result = ThreadPool(
      loop: newLoop(),
      size: size,
    )
    result.core = cast[ptr PoolCore](allocShared0(sizeof(PoolCore)))
    initLock(result.core.lock)
    initCond(result.core.space)

    # The tick observer is created here and cancelled during teardown — born
    # and buried on the constructing thread, executing only on the dispatch
    # thread in between.
    let shell = result
    let core = result.core
    let obsCb = proc(value: uint64) {.closure.} =
      {.cast(gcsafe).}:
        drainDone(core)
        if core.tearingDown and core.workersJoined:
          shell.loop.stop()
    discard result.loop.observe(cast[ptr uint64](addr result.core.doneTick),
                                obsCb)
    # NOTE: the keep-alive heartbeat is registered by the dispatch thread
    # itself (see dispatcherMain) so the interval closure is created AND
    # destroyed on the thread that runs it.

    # Give the dispatcher its own owning handle to the loop so its lifetime
    # is independent of the shell's stack copies.
    var lh = result.loop                 # incref: second owner
    result.loopHandle = cast[pointer](lh)
    wasMoved(lh)                         # handle now owns that count

    let darg = cast[ptr DispArg](allocShared0(sizeof(DispArg)))
    darg.core = result.core
    darg.loopRaw = result.loopHandle
    result.darg = darg

    result.workers = newSeq[Thread[ptr PoolCore]](size)
    for i in 0 ..< size:
      createThread(result.workers[i], workerMain, result.core)
    createThread(result.dispatcher, dispatcherMain, darg)

  proc getLoop*(pool: ThreadPool): Loop =
    ## The pool's private event loop (runs on its dispatch thread). Result
    ## callbacks fire here. Advanced use: host additional timers/sockets on
    ## it — they share the dispatch thread with result delivery, so
    ## long-running work belongs in `submitWork`, not in callbacks hosted
    ## here.
    ##
    ## Threading rule: register timers/watchers FROM the dispatch thread
    ## (e.g. from inside a result callback). Callbacks registered from a
    ## foreign thread are executed and destroyed by the dispatch thread,
    ## which trips ARC/ORC's single-owner release discipline. Must not be
    ## called after teardown.
    pool.loop

  proc teardownImpl(pool: ThreadPool, discardQueued: bool) =
    ## Shared shutdown path. Ordering:
    ## 1. flag + broadcast under the queue lock — workers wake and exit
    ##    (draining first unless discarding; discarded boxes are released by
    ##    the workers themselves)
    ## 2. join workers — in-flight jobs finished publishing their results
    ## 3. mark workers-joined + bump the tick — the observer (on the dispatch
    ##    thread) drains every outstanding result, then sees the sentinel and
    ##    stops the loop
    ## 4. join the dispatcher; close the loop on the constructing thread (the
    ##    same thread that created the observer closure)
    ## 5. drop the dispatcher's loop handle, free the unmanaged core, deinit
    ##    primitives
    ##
    ## Idempotent: concurrent/repeated calls are no-ops after the first.
    var already = false
    withLock(pool.core.lock):
      if pool.core.tearingDown:
        already = true
      else:
        pool.core.tearingDown = true
        if discardQueued:
          pool.core.dead = true
        else:
          pool.core.closing = true
        pool.core.space.broadcast()
    if already:
      return

    let core = pool.core
    for t in pool.workers.mitems:
      joinThread(t)

    withLock(core.lock):
      core.workersJoined = true
    discard core.doneTick.fetchAdd(1, moRelease)   # pure wake-up sentinel

    joinThread(pool.dispatcher)
    deallocShared(pool.darg)
    pool.darg = nil

    # Back on the constructing thread: bury the observer (loop.close clears
    # observers) and release the dispatcher's loop handle count.
    var lh = cast[Loop](pool.loopHandle)
    pool.loopHandle = nil
    pool.loop.close()
    wasMoved(lh)                       # handle's count dies with this scope

    deinitCond(core.space)
    deinitLock(core.lock)
    deallocShared(core)
    pool.core = nil

  proc closeThreadPool*(pool: ThreadPool) =
    ## Graceful shutdown: stop accepting new work, let the workers drain the
    ## queue (every queued job still runs and delivers), then join all
    ## threads. Blocks until the pool is fully torn down.
    ##
    ## Calling it twice is harmless; later calls return immediately even if
    ## the first teardown is still in progress.
    teardownImpl(pool, discardQueued = false)

  proc shutdownThreadPool*(pool: ThreadPool) =
    ## Immediate shutdown: stop accepting new work and DISCARD jobs that are
    ## still queued — their callbacks never fire (their boxes are released by
    ## the workers). Jobs already executing finish naturally and deliver.
    ## Blocks until all threads are joined.
    ##
    ## Calling it twice is harmless; later calls return immediately even if
    ## the first teardown is still in progress.
    teardownImpl(pool, discardQueued = true)

  # ── Submitting work ───────────────────────────────────────────────────────

  proc submitWork*[T](pool: ThreadPool,
                      job: proc (): T {.closure.},
                      cb: proc (res: T) {.closure.},
                      onError: proc (err: ref CatchableError) {.closure.} = nil): bool {.discardable.} =
    ## Queue `job` for execution on a worker thread. When the job returns,
    ## `cb(res)` is invoked on the pool's dispatch thread. If the job raises,
    ## `onError(err)` is delivered instead (and `cb` is skipped); with
    ## `onError == nil` the failure is swallowed and the pool stays healthy.
    ##
    ## Thread-safe: may be called from any thread, including from inside
    ## callbacks. Returns false once `closeThreadPool`/`shutdownThreadPool`
    ## began or after teardown completed — the job is rejected, neither
    ## callback fires.
    ##
    ## Note: `T` moves threads under single-ownership rules — keep it to
    ## values owned by exactly one thread at a time (ints, strings, seqs,
    ## fresh refs).
    if pool.core == nil:
      return false                     # already fully torn down
    var accepted = false
    var node: ptr TaskNode = nil
    var b: Box[T] = nil
    withLock(pool.core.lock):
      if not pool.core.tearingDown:
        accepted = true
        b = Box[T](job: job, cb: cb, onErrorCb: onError)
        node = newNode(runTask[T], cast[pointer](b), pool.core)
        pushWork(pool.core, node)
        pool.core.space.signal()
        wasMoved(b)                    # the node now owns the box
    # On the rejected path neither node nor box were created (the box is
    # only allocated inside the accepted branch), so there is nothing to
    # clean up here.
    true

else:
  type
    ThreadPool* = ref object
      ## Stub for -d:powpowNoThreads builds. All entry points raise.
    ThreadPoolError* = object of CatchableError

  proc newThreadPool*(size: int = 4): ThreadPool =
    ## Requires a threads-enabled build (do NOT pass -d:powpowNoThreads).
    raise newException(ThreadPoolError,
      "ThreadPool requires a threads-enabled build (remove -d:powpowNoThreads)")

  proc getLoop*(pool: ThreadPool): Loop =
    ## Requires a threads-enabled build (do NOT pass -d:powpowNoThreads).
    raise newException(ThreadPoolError,
      "ThreadPool requires a threads-enabled build (remove -d:powpowNoThreads)")

  proc submitWork*[T](pool: ThreadPool,
                      job: proc (): T {.closure.},
                      cb: proc (res: T) {.closure.},
                      onError: proc (err: ref CatchableError) {.closure.} = nil): bool {.discardable.} =
    ## Requires a threads-enabled build (do NOT pass -d:powpowNoThreads).
    raise newException(ThreadPoolError,
      "ThreadPool requires a threads-enabled build (remove -d:powpowNoThreads)")

  proc closeThreadPool*(pool: ThreadPool) =
    ## Requires a threads-enabled build (do NOT pass -d:powpowNoThreads).
    raise newException(ThreadPoolError,
      "ThreadPool requires a threads-enabled build (remove -d:powpowNoThreads)")

  proc shutdownThreadPool*(pool: ThreadPool) =
    ## Requires a threads-enabled build (do NOT pass -d:powpowNoThreads).
    raise newException(ThreadPoolError,
      "ThreadPool requires a threads-enabled build (remove -d:powpowNoThreads)")
