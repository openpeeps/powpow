# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
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
## - I/O multiplexing via kqueue (macOS/BSD), epoll (Linux), IOCP (Windows), or poll (fallback)
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
## - Non-blocking TCP client with async connect
## - Edge-triggered I/O events
## - Write buffering with automatic corking (TCP_CORK / TCP_NOPUSH)
## - Scatter-gather writes via writev
## - Zero-copy file send via sendfile (Linux sendfile, macOS sendfile, POSIX fallback)
## - Graceful shutdown with close-after-drain (`closeAfterDrain`)
## - Unix domain socket support (macOS/BSD/Linux)
## - SO_LINGER{0} for fast shutdown
## - Per-connection read buffer pooling
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
## - `poll` — POSIX fallback
## - `iocp` — Windows (I/O Completion Ports)
##
## ### Networking Common (`net/common.nim`)
## - Platform-agnostic socket API and address resolution (IPv4 + IPv6)
## - Socket options: non-blocking, SO_REUSEADDR, SO_REUSEPORT, TCP_NODELAY
## - sendfile zero-copy file transmission
## - Cross-platform error handling (EAGAIN, EINPROGRESS, etc.)
## - Auto-initialization (WSAStartup on Windows, SIGPIPE ignore on POSIX)


import powpow/[types, platform, loop, net, proto]

export types
export platform except close  # close is on Loop
export loop
export net
export proto
