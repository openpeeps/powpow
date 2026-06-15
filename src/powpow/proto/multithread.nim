## powpow/proto/multithread.nim — Multi-threaded HTTP server.
##
## Architecture:
##   ┌──────┐ ┌──────┐ ┌──────┐
##   │  W0  │ │  W1  │ │  W2  │  worker threads (each owns Loop + TcpServer)
##   │  fd  │ │  fd  │ │  fd  │  each has its own SO_REUSEPORT listen socket
##   └──────┘ └──────┘ └──────┘
##
## Each worker thread creates its own event loop + HTTP server + TCP server
## with a SO_REUSEPORT listen socket bound to the same address:port.
## The kernel distributes incoming connections across the workers.
##
## No single-threaded acceptor bottleneck, no pipe-based cross-thread
## communication — each worker accepts connections directly.
##
## Usage:
##   import powpow
##
##   let server = newMultiThreadHttpServer()
##   server.get("/") do (req: HttpRequest, res: Response):
##     res.status(Http200).send("Hello!")
##   server.listen("0.0.0.0", 9000)
##
## `listen()` blocks the main thread until Ctrl+C.
## Press Ctrl+C to stop.

import std/[cpuinfo, httpcore, posix]
import ../loop
import ../types
import ../net/tcp
import ../net/common
import httpserver

# ── Types ────────────────────────────────────────────────────────────────────

type
  RouteDef = object
    meth:    HttpMethod
    path:    string
    handler: Handler

  WorkerCtxObj = object
    wakeRd: cint
    wakeWr: cint

  WorkerCtx = ptr WorkerCtxObj

  WorkerArgObj = object
    ctx:      WorkerCtx
    routes:   seq[RouteDef]
    fallback: Handler
    idx:      int
    address:  string
    port:     int

  WorkerArg = ptr WorkerArgObj

  MultiThreadHttpServer* = ref object
    numThreads*: int
    routes:      seq[RouteDef]
    fallback:    Handler
    threads:     seq[Thread[WorkerArg]]
    contexts:    seq[WorkerCtx]
    running:     bool

# ── Helpers ──────────────────────────────────────────────────────────────────

proc registerRoutes(server: HttpServer, defs: seq[RouteDef]) =
  for r in defs:
    server.route(r.meth, r.path, r.handler)

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

# ── Worker thread ────────────────────────────────────────────────────────────

proc workerMain(arg: WorkerArg) {.thread.} =
  {.cast(gcsafe).}:
    let ctx     = arg.ctx
    let routes  = arg.routes
    let fallback = arg.fallback
    let idx     = arg.idx
    let address = arg.address
    let port    = arg.port
    freeWorkerArg(arg)

    let loop = newLoop()
    let server = newHttpServer(loop)
    server.registerRoutes(routes)
    if fallback != nil:
      server.notFound(fallback)
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

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc newMultiThreadHttpServer*(numThreads: int = 0): MultiThreadHttpServer =
  let n = if numThreads > 0: numThreads else: countProcessors()
  MultiThreadHttpServer(
    numThreads: n,
    routes:     @[],
    fallback:   nil,
    threads:    newSeq[Thread[WorkerArg]](n),
    contexts:   @[],
    running:    false,
  )

# ── Route registration ─────────────────────────────────────────────────────

proc route*(srv: MultiThreadHttpServer, meth: HttpMethod, path: string,
            handler: Handler) =
  srv.routes.add(RouteDef(meth: meth, path: path, handler: handler))

proc get*(srv: MultiThreadHttpServer, path: string, handler: Handler) =
  srv.route(HttpGet, path, handler)

proc post*(srv: MultiThreadHttpServer, path: string, handler: Handler) =
  srv.route(HttpPost, path, handler)

proc put*(srv: MultiThreadHttpServer, path: string, handler: Handler) =
  srv.route(HttpPut, path, handler)

proc patch*(srv: MultiThreadHttpServer, path: string, handler: Handler) =
  srv.route(HttpPatch, path, handler)

proc delete*(srv: MultiThreadHttpServer, path: string, handler: Handler) =
  srv.route(HttpDelete, path, handler)

proc head*(srv: MultiThreadHttpServer, path: string, handler: Handler) =
  srv.route(HttpHead, path, handler)

proc options*(srv: MultiThreadHttpServer, path: string, handler: Handler) =
  srv.route(HttpOptions, path, handler)

proc notFound*(srv: MultiThreadHttpServer, handler: Handler) =
  srv.fallback = handler

# ── Listen / Close ───────────────────────────────────────────────────────────

proc close*(srv: MultiThreadHttpServer) =
  srv.running = false
  for ctx in srv.contexts:
    if ctx.wakeWr >= 0:
      discard posix.close(ctx.wakeWr)
      ctx.wakeWr = -1

proc listen*(srv: MultiThreadHttpServer, address: string, port: int) =
  {.cast(gcsafe).}:
    srv.running = true

    for i in 0 ..< srv.numThreads:
      srv.contexts.add(newWorkerCtx())

    for i in 0 ..< srv.numThreads:
      let arg = cast[WorkerArg](alloc0(sizeof(WorkerArgObj)))
      arg.ctx      = srv.contexts[i]
      arg.routes   = srv.routes
      arg.fallback = srv.fallback
      arg.idx      = i
      arg.address  = address
      arg.port     = port
      createThread(srv.threads[i], workerMain, arg)

    echo "⚡ powpow accepting on ", address, ":", port,
         " with ", srv.numThreads, " workers (SO_REUSEPORT)"

    for i in 0 ..< srv.numThreads:
      joinThread(srv.threads[i])

    for ctx in srv.contexts:
      freeWorkerCtx(ctx)
    srv.contexts.setLen(0)
