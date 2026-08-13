# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## This is a high-performance, event notification library for Nim. It provides a low-level event loop and timer wheel,
## as well as higher-level abstractions for building TCP/UDP, HTTP and WebSocket servers. 
## 
## The library is designed to be minimal and efficient, with a focus on low-latency event handling and minimal overhead,
## providing a solid foundation for building high-performance networked applications in Nim.
## 
## ## Features
##
## ### Core Event Loop (`loop.nim`)
## - Single-threaded non-blocking reactor
## - I/O multiplexing via kqueue (macOS/BSD), epoll (Linux), IOCP (Windows),
##   poll (fallback), or the opt-in Linux io_uring backend (`io/`)
## - 4-level hierarchical timer wheel — O(1) insert/fire/cancel
## - One-shot and repeating interval timers
## - Deferred callbacks (executed before each I/O poll iteration)
## - Idle handlers (executed when no I/O events are pending)
## - Pointer-based fd watcher dispatch — zero hash-table lookups on the hot path
## - Generation-counter stale event detection
## - Dead watcher sweep with zombie/retired list for in-flight event safety
## - Thread-safe `stop()` via eventfd (Linux) or self-pipe (macOS/BSD)
## - Buffer pool for shared read buffers
## - Adaptive event capacity scaling (min 64, max 4096)
##
## ### TCP Networking (`net/tcp.nim`)
## - Non-blocking TCP server with connection pooling
## - Non-blocking TCP client with async connect (DNS resolved on the loop)
## - Edge-triggered I/O events
## - Write buffering with automatic corking (TCP_CORK / TCP_NOPUSH)
## - Scatter-gather writes via writev
## - Zero-copy file send via sendfile (Linux sendfile, macOS sendfile, POSIX fallback)
## - Graceful shutdown with close-after-drain (`closeAfterDrain`)
## - Unix domain socket support (macOS/BSD/Linux)
## - SO_LINGER{0} for fast shutdown
## - Per-connection read buffer pooling
##
## ### Async DNS (`net/dns.nim`)
## - In-loop DNS resolver (RFC 1035) — no blocking getaddrinfo, no worker threads
## - Reads /etc/hosts and /etc/resolv.conf (system resolver config)
## - A + AAAA queries with A-fallback; retries with timeout/attempts
## - TTL-based result cache + negative caching
## - `resolveAddrAsync` for users; `connect` uses it automatically
## - Numeric IP literals resolve inline (zero DNS I/O)
##
## ### OS Signals (`signal.nim`)
## - In-process `SignalRelay` pub/sub bus (listen / listenOnce / unlisten)
## - `watchOsSignal`/`watchOsSignals` deliver real OS signals through the loop
## - `OsSignal` enum: SIGHUP, SIGINT, SIGQUIT, SIGUSR1/2, SIGPIPE, SIGALRM,
##   SIGTERM, SIGURG, SIGCHLD, SIGIO
## - Platform-native delivery: signalfd (Linux), self-pipe (macOS/BSD/POSIX),
##   SetConsoleCtrlHandler Ctrl+C (Windows) — no global signal handlers
## - Graceful shutdown on SIGINT/SIGTERM without blocking the loop
##
## ### Stream I/O (`stream.nim`)
## - `IoStream` wraps an arbitrary non-blocking fd and drives it from the loop
## - Pipes, subprocess stdout, UDS and socketpair IPC; `newStreamPair` creates
##   a full-duplex channel
## - Connection-style write path: direct write drained until EAGAIN, remainder
##   buffered and flushed on Write events; 32 MiB queued-write cap
## - `pause`/`resume` read backpressure (a paused reader blocks the pipe writer)
## - `close` is the single terminal transition and fires `onClose` exactly once;
##   `closeAfterWrite` flushes then delivers EOF to the peer
## - POSIX only (Windows IOCP is sockets-only); regular files work on kqueue but
##   epoll rejects them
##
## ### UDP Networking (`net/udp.nim`)
## - Non-blocking UDP server (bind) and client (connect)
## - recvfrom / sendto for connectionless communication
## - Connected UDP sockets for peer-scoped send/recv
##
## ### HTTP/1.1 Parser (`proto/http.nim`)
## - Incremental, zero-copy parser — materialize strings lazily from byte offsets
## - O(1) method dispatch via first-byte switch
## - Pipelined request support
## - Streaming body handling via callback
## - Chunked transfer encoding
## - Body streaming to file
## - Multipart form data support
##
## ### HTTP Server (`proto/httpserver.nim`)
## - Implement your-own-router — lower-level callback-based design
## - `OnRequestCallback* = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.}`
## - Higher-level frameworks implement routing on top of this callback
## - Streaming response body
## - Static file serving with MIME type detection
## - Conditional requests (If-Modified-Since, If-None-Match)
## - Range requests with 206 Partial Content
## - Directory listing
## - CORS headers
## - Streaming multipart upload handling
## - Pipelined request-response processing
##
## ### WebSocket (`proto/ws.nim`)
## - RFC 6455 compliant
## - Standalone WebSocket server mode
## - HTTP upgrade from HttpServer routes
## - Text, binary, ping/pong, and close frames
## - Per-message deflate extension
## - Masked frame handling
##
## ### Multi-threaded HTTP Server (`proto/multithread.nim`)
## - SO_REUSEPORT kernel-level connection distribution
## - One event loop + listen socket per worker thread
## - Zero cross-thread communication — no single-threaded acceptor bottleneck
## - Graceful shutdown via shutdown pipe
##
## ### SIMD-Accelerated Scanning (`proto/simdscan.nim`)
## - SSE2-accelerated CRLF detection
## - Scalar fallback for non-x86 architectures
##
## ### Platform Abstraction (`platform/`)
## - `kqueue` — macOS/BSD (high-performance, edge-triggered)
## - `epoll` — Linux (with eventfd wake)
## - `iocp` — Windows (I/O Completion Ports)
## - `poll` — POSIX fallback
## - `io/` — Linux io_uring backend (submission-based, opt-in). Enabled with
##   `nimble --features:io_uring <cmd>`, `requires "powpow[io_uring]"`, or
##   `nim c -d:powpowIoUring`. The same public API, driven by
##   `IORING_OP_ACCEPT/RECV/SEND/CONNECT/RECVMSG/SENDMSG/...` completions
##   instead of readiness events; the generic fd-watcher API is emulated with
##   one-shot `IORING_OP_POLL_ADD`. Requires Linux >= 5.6.
##
## ### Networking Common (`net/common.nim`)
## - Platform-agnostic socket API and address resolution (IPv4 + IPv6)
## - Socket options: non-blocking, SO_REUSEADDR, SO_REUSEPORT, TCP_NODELAY
## - sendfile zero-copy file transmission
## - Cross-platform error handling (EAGAIN, EINPROGRESS, etc.)
## - Auto-initialization (WSAStartup on Windows, SIGPIPE ignore on POSIX)


import powpow/types
export types

when iouEnabled:
  import powpow/[loop, net, proto, signal, fswatch]
  export loop  # close is on Loop
  export net
  export proto
  export signal
  export fswatch
else:
  import powpow/[platform, loop, net, proto, signal, fswatch]
  export platform except close  # close is on Loop
  export loop
  export net
  export proto
  export signal
  export fswatch