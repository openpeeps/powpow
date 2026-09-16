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
  import ./httpserver

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
      for p in ports:
        server.listen(address, p)
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
    ## all `ports` with SO_REUSEPORT, sharing the same handler.
    if ports.len == 0:
      raise newException(ValueError, "listen: at least one port is required")
    {.gcsafe.}:
      srv.running = true
      for i in 0 ..< srv.numThreads:
        srv.contexts.add(newWorkerCtx())
      for i in 0 ..< srv.numThreads:
        let arg = cast[WorkerArg](alloc0(sizeof(WorkerArgObj)))
        arg.ctx     = srv.contexts[i]
        arg.handler = srv.handler
        arg.idx     = i
        arg.address = address
        arg.ports   = @ports
        createThread(srv.threads[i], workerMain, arg)

      if srv.onStartCb != nil: srv.onStartCb(srv.numThreads)

      for i in 0 ..< srv.numThreads:
        joinThread(srv.threads[i])
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
