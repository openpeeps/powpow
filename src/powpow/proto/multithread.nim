# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/proto/multithread.nim — Multi-threaded HTTP server.
##
## Each worker thread creates its own event loop + HTTP server + TCP server
## with a SO_REUSEPORT listen socket bound to the same address:port.
## The kernel distributes incoming connections across the workers.
## No single-threaded acceptor bottleneck, no cross-thread communication.
##
## Usage:
##   ```nim
##   let server = newHttpServer(countProcessors())
##   server.start do (req: HttpRequest, res: HttpResponse):
##     if req.getPath() == "/":
##       res.status(Http200).send("Hello!")
##   , "0.0.0.0", Port(9000)
##   ```

when not defined(windows):
  import std/[cpuinfo, posix]
  import ../loop
  import ../types
  import ../net/common
  import ../net/tcp
  import ./httpserver
  import ./http2conn
  import ./hpack

  # Workers share ONE listen socket instead of each binding its own. Linux and
  # FreeBSD load-balance a SO_REUSEPORT group in the kernel, so one socket per
  # worker scales with no shared state. Darwin permits the shared bind but
  # hands every connection to a single member of the group (and has no
  # SO_REUSEPORT_LB to change that), so per-worker sockets there leave every
  # worker but one idle. Verified on macOS 14/15: 240 connections across a
  # 12-socket group all landed on one socket. Sharing one fd means every worker
  # registers it in its own loop and whichever accepts first wins.
  const SharedListenFd = when defined(macosx): true
                          else: false

  const sharedFdPath = SharedListenFd and not iouEnabled
    ## Single compile-time gate for the shared-listener path, so the runtime
    ## decision and the availability of `createListenSocket`/`adoptListenFd`
    ## cannot drift apart — a runtime `if` over a missing proc does not
    ## compile, and a `when` over an unreachable branch is dead code. These
    ## procs are part of the readiness backends only; the io_uring backend
    ## (Linux-only) does not define them, while `SharedListenFd` requires
    ## macOS, so the conjunction drops nothing reachable.

  const WarmWorkerPoolSize {.intdefine.} = 128
    ## Entries pre-warmed per pool per worker when `-d:powpowWarmWorkers` is
    ## set. Smaller than the single-loop default (256): workers multiply it by
    ## core count, so the default trades a little first-request allocation for
    ## faster boot and less idle RSS. Opt-in because it costs ~0.5MB per worker
    ## up front and slows worker spawn.

  type
    WorkerCtxObj = object
      wakeRd: cint
      wakeWr: cint

    WorkerCtx = ptr WorkerCtxObj

    WorkerArgObj = object
      ctx:     WorkerCtx
      handler: OnRequestCallback
      idx:     int
      address: string
      ports:   seq[int]
      listenFds: seq[SocketHandle]  # shared-socket mode; empty = bind per worker

    WorkerArg = ptr WorkerArgObj

    MultiThreadHttpServer* = ref object
      numThreads*: int
      handler:     OnRequestCallback
      onStartCb:   proc(numThreads: int) {.gcsafe.}
      threads:     seq[Thread[WorkerArg]]
      contexts:    seq[WorkerCtx]
      running:     bool

  proc newWorkerCtx(): WorkerCtx =
    result = cast[WorkerCtx](alloc0(sizeof(WorkerCtxObj)))
    var fds: array[2, cint]
    if pipe(fds) != 0:
      raise newException(OSError, "powpow: pipe() failed for shutdown pipe")
    result.wakeRd = fds[0]
    result.wakeWr = fds[1]
    setNonBlocking(SocketHandle(fds[0]))
    setNonBlocking(SocketHandle(fds[1]))

  proc freeWorkerCtx(ctx: WorkerCtx) =
    if ctx.wakeRd >= 0: discard posix.close(ctx.wakeRd)
    if ctx.wakeWr >= 0: discard posix.close(ctx.wakeWr)
    dealloc(ctx)

  proc freeWorkerArg(arg: WorkerArg) =
    reset(arg[])
    dealloc(arg)

  proc workerMain(arg: WorkerArg) {.thread.} =
    {.gcsafe.}:
      let ctx     = arg.ctx
      let handler = arg.handler
      let address = arg.address
      let ports   = arg.ports
      let listenFds = arg.listenFds
      freeWorkerArg(arg)

      let loop = newLoop()
      let server = newHttpServer(loop, populate = false)
      server.handler = handler

      loop.register(ctx.wakeRd.int, {Read}) do (fd: int, ev: set[EventType]):
        var buf: array[256, byte]
        while true:
          let n = posix.read(fd.cint, cast[pointer](addr buf[0]), buf.len)
          if n == 0:
            loop.stop()
            break
          if n < 0: break
      when sharedFdPath:
        if listenFds.len > 0:
          # Shared-socket mode: adopt the parent's listener in this loop. Every
          # worker registers the same fd; one accept() wins per connection.
          for fd in listenFds:
            server.adoptListenFd(fd)
        else:
          for p in ports:
            server.listen(address, p)
      else:
        for p in ports:
          server.listen(address, p)
      when defined(powpowWarmWorkers):
        # Opt-in warmup AFTER listen, so the connPool warms the live bound
        # server instead of a throwaway unbound one (see listen() migration).
        server.populatePools(WarmWorkerPoolSize)
      loop.run()
      server.close()
      loop.close()

  proc newHttpServer*(numThreads: int): MultiThreadHttpServer =
    let n = if numThreads > 0: numThreads else: countProcessors()
    MultiThreadHttpServer(
      numThreads: n,
      handler:    nil,
      threads:    newSeq[Thread[WorkerArg]](n),
      contexts:   @[],
      running:    false,
    )

  proc listenMulti(srv: MultiThreadHttpServer, address: string, ports: openArray[int]) =
    ## Internal helper shared by single- and multi-port overloads.
    ## Listen on multiple ports (same address). Additive: each worker binds
    ## all `ports` with SO_REUSEPORT, sharing the same handler — or adopts one
    ## shared listener per port where the kernel does not load-balance a
    ## SO_REUSEPORT group (see `SharedListenFd`).
    if ports.len == 0:
      raise newException(ValueError, "listen: at least one port is required")
    {.gcsafe.}:
      srv.running = true

      var sharedFds: seq[SocketHandle]
      when sharedFdPath:
        if SharedListenFd:
          # Bind here, in the parent, so every worker adopts the same fd. On a
          # failure close whatever already succeeded rather than leaking.
          try:
            for p in ports:
              sharedFds.add(createListenSocket(address, p))
          except CatchableError:
            for fd in sharedFds:
              discard posix.close(fd)
            raise

      for i in 0 ..< srv.numThreads:
        srv.contexts.add(newWorkerCtx())
      for i in 0 ..< srv.numThreads:
        let arg = cast[WorkerArg](alloc0(sizeof(WorkerArgObj)))
        arg.ctx     = srv.contexts[i]
        arg.handler = srv.handler
        arg.idx     = i
        arg.address = address
        arg.ports   = @ports
        arg.listenFds = if sharedFdPath: sharedFds else: @[]
        createThread(srv.threads[i], workerMain, arg)

      if srv.onStartCb != nil: srv.onStartCb(srv.numThreads)

      for i in 0 ..< srv.numThreads:
        joinThread(srv.threads[i])
      # Workers only registered the shared listener, so the parent still owns
      # it; close it once every worker has stopped.
      for fd in sharedFds:
        discard posix.close(fd)
      for ctx in srv.contexts:
        freeWorkerCtx(ctx)
      srv.contexts.setLen(0)

  proc listen*(srv: MultiThreadHttpServer, address: string, port: int) =
    srv.listenMulti(address, [port])

  proc listen*(srv: MultiThreadHttpServer, address: string, ports: openArray[int]) =
    srv.listenMulti(address, ports)

  proc listen*(srv: MultiThreadHttpServer, address: string, port: Port) =
    srv.listenMulti(address, [port.int])

  proc listen*(srv: MultiThreadHttpServer, address: string, ports: openArray[Port]) =
    var intPorts = newSeq[int](ports.len)
    for i, p in ports:
      intPorts[i] = p.int
    srv.listenMulti(address, intPorts)

  proc start*(srv: MultiThreadHttpServer, cb: OnRequestCallback,
              address: string, port: int) =
    srv.handler = cb
    srv.listen(address, port)

  proc start*(srv: MultiThreadHttpServer, cb: OnRequestCallback,
              address: string, ports: varargs[int]) =
    ## Multi-port variant: `srv.start(handler, "0.0.0.0", 9000, 9001)`
    if ports.len == 0:
      raise newException(ValueError, "start: at least one port is required")
    srv.handler = cb
    srv.listen(address, ports)

  proc start*(srv: MultiThreadHttpServer, cb: OnRequestCallback,
              address: string, port: Port) =
    ## Port variant so the same call works for both `HttpServer` and
    ## `MultiThreadHttpServer`: `srv.start(handler, "0.0.0.0", Port(9000))`.
    srv.handler = cb
    srv.listen(address, port.int)

  proc start*(srv: MultiThreadHttpServer, cb: OnRequestCallback,
              address: string, ports: varargs[Port]) =
    ## Multi-port Port variant: `srv.start(handler, "0.0.0.0", Port(9000), Port(9001))`
    if ports.len == 0:
      raise newException(ValueError, "start: at least one port is required")
    srv.handler = cb
    var intPorts = newSeq[int](ports.len)
    for i, p in ports:
      intPorts[i] = p.int
    srv.listen(address, intPorts)

  proc close*(srv: MultiThreadHttpServer) =
    srv.running = false
    for ctx in srv.contexts:
      if ctx.wakeWr >= 0:
        discard posix.close(ctx.wakeWr)
        ctx.wakeWr = -1

  # ── Multi-threaded H2 (h2c) server ──────────────────────────────────────
  #
  # Same shape as the H1 workers: one event loop + H2Server per thread on a
  # SO_REUSEPORT socket. All H2 connection state is per-connection (owned
  # by the accepting thread's loop); the only shared global is the
  # read-only Huffman decode tree, pre-built in `start` before spawning.

  type
    H2WorkerArgObj = object
      ctx:     WorkerCtx
      handler: OnH2RequestCallback
      address: string
      port:    int

    H2WorkerArg = ptr H2WorkerArgObj

    MultiThreadH2Server* = ref object
      numThreads*: int
      handler:     OnH2RequestCallback
      threads:     seq[Thread[H2WorkerArg]]
      contexts:    seq[WorkerCtx]
      running:     bool

  proc freeH2WorkerArg(arg: H2WorkerArg) =
    reset(arg[])
    dealloc(arg)

  proc h2WorkerMain(arg: H2WorkerArg) {.thread.} =
    {.gcsafe.}:
      let ctx     = arg.ctx
      let handler = arg.handler
      let address = arg.address
      let port    = arg.port
      freeH2WorkerArg(arg)

      let loop = newLoop()
      let server = newH2Server(loop, handler)
      server.listen(address, port)

      loop.register(ctx.wakeRd.int, {Read}) do (fd: int, ev: set[EventType]):
        var buf: array[256, byte]
        while true:
          let n = posix.read(fd.cint, cast[pointer](addr buf[0]), buf.len)
          if n == 0:
            loop.stop()
            break
          if n < 0: break
      loop.run()
      server.close()
      loop.close()

  proc newMultiThreadH2Server*(numThreads: int): MultiThreadH2Server =
    let n = if numThreads > 0: numThreads else: countProcessors()
    MultiThreadH2Server(
      numThreads: n,
      handler:    nil,
      threads:    newSeq[Thread[H2WorkerArg]](n),
      contexts:   @[],
      running:    false,
    )

  proc start*(srv: MultiThreadH2Server, handler: OnH2RequestCallback,
              address: string, port: int) =
    ## Serve h2c on `address:port` with `numThreads` workers. Blocks until
    ## `close` (like the H1 variant). The handler must be thread-safe
    ## (capture-nothing closures are ideal).
    srv.handler = handler
    srv.running = true
    initHuffman()  # pre-build shared decode tree before spawning workers
    for i in 0 ..< srv.numThreads:
      srv.contexts.add(newWorkerCtx())
    for i in 0 ..< srv.numThreads:
      let arg = cast[H2WorkerArg](alloc0(sizeof(H2WorkerArgObj)))
      arg.ctx     = srv.contexts[i]
      arg.handler = srv.handler
      arg.address = address
      arg.port    = port
      createThread(srv.threads[i], h2WorkerMain, arg)
    for i in 0 ..< srv.numThreads:
      joinThread(srv.threads[i])
    for ctx in srv.contexts:
      freeWorkerCtx(ctx)
    srv.contexts.setLen(0)

  proc close*(srv: MultiThreadH2Server) =
    srv.running = false
    for ctx in srv.contexts:
      if ctx.wakeWr >= 0:
        discard posix.close(ctx.wakeWr)
        ctx.wakeWr = -1
