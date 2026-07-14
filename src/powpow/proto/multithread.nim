# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
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
##   let server = newMultiThreadHttpServer()
##   server.start do (req: HttpRequest, res: HttpResponse):
##     if req.getPath() == "/":
##       res.status(Http200).send("Hello!")
##   , "0.0.0.0", 9000
##   ```

when not defined(windows):
  import std/[cpuinfo, httpcore, posix]
  import ../loop
  import ../types
  import ../net/tcp
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
      port:    int

    WorkerArg = ptr WorkerArgObj

    MultiThreadHttpServer* = ref object
      numThreads*: int
      handler:     OnRequestCallback
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
      let idx     = arg.idx
      let address = arg.address
      let port    = arg.port
      freeWorkerArg(arg)

      let loop = newLoop()
      let server = newHttpServer(loop)
      server.handler = handler
      server.ensureTcpServer()

      loop.register(ctx.wakeRd.int, {Read}) do (fd: int, ev: set[EventType]):
        var buf: array[256, byte]
        while true:
          let n = posix.read(fd.cint, cast[pointer](addr buf[0]), buf.len)
          if n == 0:
            loop.stop()
            break
          if n < 0: break

      echo "  worker #", idx, " ready"
      server.listen(address, port)
      loop.run()
      server.close()
      loop.close()

  proc newMultiThreadHttpServer*(numThreads: int = 0): MultiThreadHttpServer =
    let n = if numThreads > 0: numThreads else: countProcessors()
    MultiThreadHttpServer(
      numThreads: n,
      handler:    nil,
      threads:    newSeq[Thread[WorkerArg]](n),
      contexts:   @[],
      running:    false,
    )

  proc listen*(srv: MultiThreadHttpServer, address: string, port: int) =
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
        arg.port    = port
        createThread(srv.threads[i], workerMain, arg)
      echo "⚡ powpow accepting on ", address, ":", port,
           " with ", srv.numThreads, " workers (SO_REUSEPORT)"
      for i in 0 ..< srv.numThreads:
        joinThread(srv.threads[i])
      for ctx in srv.contexts:
        freeWorkerCtx(ctx)
      srv.contexts.setLen(0)

  proc start*(srv: MultiThreadHttpServer, cb: OnRequestCallback,
              address: string, port: int) =
    srv.handler = cb
    srv.listen(address, port)

  proc close*(srv: MultiThreadHttpServer) =
    srv.running = false
    for ctx in srv.contexts:
      if ctx.wakeWr >= 0:
        discard posix.close(ctx.wakeWr)
        ctx.wakeWr = -1
