## powpow/proto/multithread.nim — Multi-threaded HTTP server.
##
## Architecture:
##   ┌─────────────────┐
##   │  Acceptor thread │  (main thread — blocking accept)
##   │  round-robin     │
##   └──┬─────┬─────┬──┘
##      │     │     │     lock-protected fd queue + pipe wake
##   ┌──▼─┐┌──▼─┐┌──▼─┐
##   │ W0 ││ W1 ││ W2 │  worker threads (each own event loop + HttpServer)
##   └────┘└────┘└────┘
##
## A single acceptor thread does blocking `accept()` and distributes
## connections round-robin to N worker threads via a lock-protected
## queue.  A pipe per worker wakes the event loop with zero latency,
## so there is no polling overhead.
##
## This gives the acceptor full control over load balancing (critical
## for low connection counts) and avoids the overhead of N independent
## listen sockets (SO_REUSEPORT).
##
## Usage:
##   import powpow
##
##   let server = newMultiThreadHttpServer()
##   server.get("/") do (req: HttpRequest, res: Response):
##     res.status(Http200).send("Hello!")
##   server.listen("0.0.0.0", 9000)
##
## `listen()` blocks on the main thread (runs the acceptor).
## Press Ctrl+C to stop.

import std/[cpuinfo, httpcore, locks, posix]
import ../loop
import ../types
import ../net/tcp
import ../net/common
import httpserver

# ── Types ────────────────────────────────────────────────────────────────────

type
  RouteDef = object
    # A stored route definition, copied to each worker thread.
    meth:    HttpMethod
    path:    string
    handler: Handler

  WorkerCtxObj = object
    # Shared state between the acceptor thread and one worker thread.
    # Allocated on the unmanaged heap so it outlives any GC interaction.
    lock:     Lock             # Protects `incoming`
    incoming: seq[cint]        # Pending client fds from the acceptor
    wakeRd:   cint             # Pipe read-end  (registered in event loop)
    wakeWr:   cint             # Pipe write-end  (acceptor writes here)

  WorkerCtx = ptr WorkerCtxObj

  WorkerArgObj = object
    # Heap-allocated argument passed to each worker thread.
    ctx:      WorkerCtx
    routes:   seq[RouteDef]
    fallback: Handler
    idx:      int

  WorkerArg = ptr WorkerArgObj

  MultiThreadHttpServer* = ref object
    ## A multi-threaded HTTP server with a single acceptor and N workers.
    numThreads*: int
    routes:      seq[RouteDef]
    fallback:    Handler
    threads:     seq[Thread[WorkerArg]]
    contexts:    seq[WorkerCtx]
    listenFd:    cint
    running:     bool

# ── Helpers ──────────────────────────────────────────────────────────────────

proc registerRoutes(server: HttpServer, defs: seq[RouteDef]) =
  ## Register all stored route definitions on an HTTP server.
  for r in defs:
    server.route(r.meth, r.path, r.handler)

proc newWorkerCtx(): WorkerCtx =
  ## Allocate and initialise a worker context (pipe + lock).
  result = cast[WorkerCtx](alloc0(sizeof(WorkerCtxObj)))
  initLock(result.lock)
  result.incoming = @[]
  var fds: array[2, cint]
  if pipe(fds) != 0:
    raise newException(OSError, "powpow: pipe() failed for worker wake fd")
  result.wakeRd = fds[0]
  result.wakeWr = fds[1]
  setNonBlocking(SocketHandle(fds[0]))
  setNonBlocking(SocketHandle(fds[1]))

proc freeWorkerCtx(ctx: WorkerCtx) =
  ## Release all resources held by a worker context.
  deinitLock(ctx.lock)
  if ctx.wakeRd >= 0: discard posix.close(ctx.wakeRd)
  if ctx.wakeWr >= 0: discard posix.close(ctx.wakeWr)
  reset(ctx.incoming)
  dealloc(ctx)

proc freeWorkerArg(arg: WorkerArg) =
  ## Release the heap-allocated spawn argument (managed fields + unmanaged mem).
  reset(arg[])
  dealloc(arg)

# ── Worker thread ────────────────────────────────────────────────────────────

proc workerMain(arg: WorkerArg) {.thread.} =
  ## Entry point for each worker thread.
  ## Creates its own Loop + HttpServer, registers routes, wires the
  ## wake-pipe into the event loop, and runs until shutdown.
  {.cast(gcsafe).}:
    let ctx      = arg.ctx
    let routes   = arg.routes
    let fallback = arg.fallback
    let idx      = arg.idx
    freeWorkerArg(arg)

    let loop = newLoop()
    let server = newHttpServer(loop)
    server.registerRoutes(routes)
    if fallback != nil:
      server.notFound(fallback)
    server.ensureTcpServer()

    # Wire the pipe read-end into the event loop.
    # When the acceptor pushes an fd it writes a byte → this callback fires.
    loop.register(ctx.wakeRd.int, {Read}) do (fd: int, ev: set[EventType]):
      # 1. Drain the wake pipe (non-blocking, read until EAGAIN / EOF)
      var shutdown = false
      var buf: array[256, byte]
      while true:
        let n = posix.read(ctx.wakeRd, addr buf[0], buf.len)
        if n == 0:
          shutdown = true    # write-end closed → shutdown signal
          break
        if n < 0: break      # EAGAIN → drained

      # 2. Drain all pending client fds under the lock
      var fds: seq[cint]
      withLock ctx.lock:
        fds = ctx.incoming
        ctx.incoming = @[]

      # 3. Inject each fd into the HTTP server's event loop
      for cfd in fds:
        server.addConnection(SocketHandle(cfd))

      # 4. If the pipe was closed, stop this worker's event loop
      if shutdown:
        loop.stop()

    echo "  worker #", idx, " ready"
    loop.run()
    server.close()
    loop.close()

# ── Acceptor (runs on main thread) ───────────────────────────────────────────

proc acceptLoop(srv: MultiThreadHttpServer, address: string, port: int) =
  # Blocking accept loop. Round-robins connections to worker threads.
  let addrBuf = resolveAddr(address, port, SOCK_STREAM)
  let fd = socket(cast[ptr Sockaddr](addr addrBuf).sa_family.cint,
                  SOCK_STREAM.cint, 0)
  if fd.cint < 0:
    raise newException(NetError, "socket() failed")

  setReuseAddr(SocketHandle(fd))
  setReusePort(SocketHandle(fd))

  let sLen = getSockLen(addr addrBuf)
  if bindSocket(fd, cast[ptr Sockaddr](addr addrBuf), sLen) < 0:
    discard posix.close(fd)
    raise newException(NetError, "bind() failed")

  if posix.listen(fd, SOMAXCONN) < 0:
    discard posix.close(fd)
    raise newException(NetError, "listen() failed")

  srv.listenFd = fd.cint
  echo "⚡ powpow accepting on ", address, ":", port,
       " with ", srv.numThreads, " workers"

  var next = 0  # round-robin index

  while srv.running:
    var clientAddr: Sockaddr_storage
    var addrLen: SockLen = sizeof(clientAddr).SockLen
    let clientFd = posix.accept(fd,
                                cast[ptr Sockaddr](addr clientAddr),
                                addr addrLen)
    if clientFd.cint < 0:
      if errno == EINTR: continue
      break  # listen fd closed or fatal error

    # TCP_NODELAY for low-latency HTTP responses
    setTcpNoDelay(SocketHandle(clientFd))

    # Round-robin to next worker
    let ctx = srv.contexts[next]
    next = (next + 1) mod srv.numThreads

    withLock ctx.lock:
      ctx.incoming.add(clientFd.cint)

    # Wake the worker's event loop (1 byte = 1 pending accept)
    var one: byte = 1
    discard posix.write(ctx.wakeWr, addr one, 1)

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc newMultiThreadHttpServer*(numThreads: int = 0): MultiThreadHttpServer =
  ## Create a new multi-threaded HTTP server.
  ##
  ## - `numThreads = 0` (default) → one worker per CPU core.
  ## - Routes are registered via the `get`, `post`, … helpers,
  ##   then `listen()` starts the workers and acceptor.
  let n = if numThreads > 0: numThreads else: countProcessors()
  MultiThreadHttpServer(
    numThreads: n,
    routes:     @[],
    fallback:   nil,
    threads:    newSeq[Thread[WorkerArg]](n),
    contexts:   @[],
    listenFd:   -1,
    running:    false,
  )

# ── Route registration (mirrors HttpServer API) ─────────────────────────────

proc route*(srv: MultiThreadHttpServer, meth: HttpMethod, path: string,
            handler: Handler) =
  ## Register a route handler.
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
  ## Register a catch-all handler for unmatched routes.
  srv.fallback = handler

# ── Listen / Close ───────────────────────────────────────────────────────────

proc close*(srv: MultiThreadHttpServer) =
  ## Signal all workers to stop.  Closes the listen socket (unblocks
  ## the acceptor) and each worker's pipe write-end (wakes event loops).
  srv.running = false

  # Close listen socket → accept() returns -1
  if srv.listenFd >= 0:
    discard posix.close(srv.listenFd)
    srv.listenFd = -1

  # Close pipe write-ends → workers see EOF → loop.stop()
  for ctx in srv.contexts:
    if ctx.wakeWr >= 0:
      discard posix.close(ctx.wakeWr)
      ctx.wakeWr = -1

proc listen*(srv: MultiThreadHttpServer, address: string, port: int) =
  ## Start the multi-threaded server.
  ##
  ## Spawns `numThreads` worker threads, then runs the acceptor on
  ## the **main thread** (this call blocks until the process exits
  ## or [`close`](#close,MultiThreadHttpServer) is called).
  {.cast(gcsafe).}:
    srv.running = true

    # 1. Create per-worker contexts (pipe + lock)
    for i in 0 ..< srv.numThreads:
      srv.contexts.add(newWorkerCtx())

    # 2. Spawn all worker threads
    for i in 0 ..< srv.numThreads:
      let arg = cast[WorkerArg](alloc0(sizeof(WorkerArgObj)))
      arg.ctx      = srv.contexts[i]
      arg.routes   = srv.routes
      arg.fallback = srv.fallback
      arg.idx      = i
      createThread(srv.threads[i], workerMain, arg)

    # 3. Main thread runs the accept loop (blocks here)
    srv.acceptLoop(address, port)

    # 4. Acceptor returned — close pipe write-ends to signal workers
    for ctx in srv.contexts:
      if ctx.wakeWr >= 0:
        discard posix.close(ctx.wakeWr)
        ctx.wakeWr = -1

    # 5. Join all worker threads
    for i in 0 ..< srv.numThreads:
      joinThread(srv.threads[i])

    # 6. Free contexts
    for ctx in srv.contexts:
      freeWorkerCtx(ctx)
    srv.contexts.setLen(0)
