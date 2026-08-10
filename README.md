<p align="center">
  <img src="https://github.com/openpeeps/powpow/blob/main/.github/powpow_logo.png" width="80px"><br>
  PowPow 💥  A high-performance event notification library for Nim
</p>

<p align="center">
  <code>nimble install powpow</code>
</p>

<p align="center">
  <a href="https://openpeeps.github.io/powpow">API reference</a><br>
  <img src="https://github.com/openpeeps/powpow/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/openpeeps/powpow/workflows/docs/badge.svg" alt="Github Actions">
</p>

## 😍 Key Features
- High-performance, event-driven networking library for Nim
- Support for low-level **UDP, TCP sockets**
- Built-in HTTP/1.1 server implementation
- Built-in **WebSocket support** with standalone and upgrade modes
- **TLS/SSL** support (implicit + STARTTLS-style upgrades)
- **Signal/Relay** system for in-process event dispatch
- Built-in **rate limiting** per client IP
- **HTTP over Unix Domain Sockets** (UDS) support for super fast local IPC
- **Zero-copy file transmission** using `sendfile` (Unix) and `TransmitFile` (Windows)
- Chunked Request Body support for streaming uploads and large payloads
- Memory-efficient Multipart Form Data parsing and Raw Body handling for file uploads
- SIMD-accelerated parsing and formatting of HTTP messages
- Built on top of `epoll` (Linux), and `kqueue` (BSD, macOS), `IOCP` (Windows)
- Support for edge-triggered and level-triggered event notification
- Support for multiple event loops and multi-threaded applications
- Support for MIME type detection based on file extensions
- FileSystem Monitoring via `inotify` (Linux) and `kqueue` (BSD, macOS) (Windows - not yet implemented)

> [!NOTE]
> 💥 PowPow is now available in [Supranim](https://github.com/supranim/supranim) as a backend. Just switch `--features:powpow` when compiling your Supranim app!

> [!WARNING]
> 💥 This library is not production-ready and may contain bugs and security vulnerabilities. It has been tested on Linux and macOS, but may not work on all platforms. **Use it, test it, and do not hesitate to report any issues you find!** 💥 

## Examples (the fun part)
Most web servers out there are all rainbows and flowers, until you upload or stream a file, and it transforms into a nightmare at runtime. PowPow is slowly moving toward a production-ready server. Everything below is runnable and lives in the `examples/` directory.

- `httpserver.nim` the classic. A tiny, functional HTTP/1.1 server

- `httpserver_threads.nim` the same server, but it spawns **one event loop per CPU core** and binds them all to the same port via `SO_REUSEPORT`. The kernel load-balances connections across workers for you

- `upload_server.nim` file uploads done right, using `pkg/multipart` two ways:
  - `/upload/raw` raw body streamed straight to disk via `streamToFile()`
  - `/upload/stream` multipart parsed on the fly with `getMultipart()`
  - Both keep RAM low and your hard drive honest. Runnable example: [upload_server.nim](https://github.com/openpeeps/powpow/blob/main/examples/upload_server.nim)

- `stream_server.nim`, it streams and serves a **2.76 GB** `Big_Buck_Bunny_4K.webm` (get it from here > https://en.wikipedia.org/wiki/File:Big_Buck_Bunny_4K.webm) with three different APIs:
  - `/video` zero-copy media streaming with chunk limiting (1 MB per response), always keep-alive, always Range-aware
  - `/download` `Content-Disposition: attachment`, optional Range support
  - `/resume` full `serveFile` with `If-None-Match`, `If-Modified-Since`, `If-Range` and Range handling, `304`/`206` and all. Resume support built in, because your users *will* close the laptop lid mid-download

- `wsserver.nim` a standalone WebSocket server. The upgrade handshake is handled internally; there are no HTTP routes at all

- `wsupgrade.nim` HTTP **and** WebSocket on the same port. `curl localhost:9000/` for HTML, `websocat ws://localhost:9000/ws` for real-time. One process, one port, two protocols. The browser test page (`wsclient.html`) is included so you can watch it work live

- `ratelimit_server.nim` built-in sliding-window rate limiting per client IP

- `fswatch.nim` file system monitoring via the same event loop (`inotify` on Linux, `kqueue` on macOS/BSD)

- `tcp_chat.nim` a real multi-client chat room on the raw TCP layer, no HTTP in sight. The server broadcasts every client's bytes to everyone else; `nc 127.0.0.1 9010` and start arguing with yourself in two terminals

- `tcp_client.nim` the chat's better half an interactive stdin client for `tcp_chat.nim`. Stdin is polled non-blockingly on the loop, so replies print while you are still typing

- `tcp_proxy.nim` a TCP reverse proxy / load balancer: it accepts clients on `:9020`, opens an upstream connection to a backend on `:9021`, and pipes bytes both ways, buffering anything that arrives before the upstream is ready. `nc 127.0.0.1 9020`, type, watch the backend echo come back

- `udp_echo.nim` UDP done politely: a bound socket that echoes every datagram back to its sender (`bindUdp` + `sendTo`), plus a `--client` mode that pings the server with `connectUdp`. `nc -u` works too

- `static_server.nim` a static site server: `serveStatic` from `examples/www/` (zero-copy `sendFile`, path-traversal and symlink-escape safe), CORS headers on everything, and a tiny `/api/time` JSON endpoint. A whole website, served from one process and a folder of files

- `uds_server.nim` HTTP over a Unix domain socket, no TCP stack involved. The whole request stays on the machine, which is great if you and your microservice have agreed to never speak over the network again. `curl --unix-socket /tmp/powpow.sock http://localhost/hello`
- `tls_server.nim` an HTTPS server with an embedded self-signed certificate. `curl -k https://localhost:9443/hello` and the TLS handshake happens before your coffee does

- `signal_bus.nim` an in-process pub/sub event bus (`SignalRelay`): an HTTP endpoint emits named events and subscribers react to them, including `listenOnce` and manual `unlisten`. Server-side events without a server-side framework

- `timers_scheduler.nim` a guided tour of the timer wheel: one-shot timers, repeating intervals, deferred callbacks, and idle handlers, all ticking on the same loop for ~8 seconds before politely stopping

- `ws_chat.nim` a multi-client WebSocket chat with broadcast. Open `http://localhost:9006` in two browser tabs, type in one, and enjoy the other one agreeing with you. The browser page lives in `ws_chat.html`

## Dummy Benchmarks
**Pow Pow is the #1 fastest HTTP server** from [Web Framework Benchmarks](https://web-frameworks-benchmark.netlify.app/result). Find the wrk-based benchmark I manually ran via Github Actions ([see bench.yml](https://github.com/openpeeps/powpow/blob/main/.github/workflows/bench.yml))

- Single-threaded (keep-alive)
```
💥 powpow HTTP server listening on http://localhost:9000
  Press Ctrl+C to stop
Running 5s test @ http://127.0.0.1:9000/
  4 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     1.02ms   61.67us   3.25ms   81.86%
    Req/Sec    24.63k   818.23    26.67k    68.00%
  489946 requests in 5.00s, 277.55MB read
Requests/sec:  97965.24
Transfer/sec:     55.50MB
```

- Single-threaded (connection close)
```
💥 powpow HTTP server listening on http://localhost:9000
  Press Ctrl+C to stop
Running 5s test @ http://127.0.0.1:9000/
  4 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     1.97ms  202.12us   4.22ms   80.09%
    Req/Sec     9.13k     3.62k   18.16k    71.43%
  184469 requests in 5.10s, 103.62MB read
Requests/sec:  36174.22
Transfer/sec:     20.32MB
```

- Multi-threaded (keep-alive)
```
  worker #0 ready
  worker #2 ready
💥 powpow accepting on 0.0.0.0:9000 with 4 workers (SO_REUSEPORT)
  worker #1 ready
  worker #3 ready
Running 5s test @ http://127.0.0.1:9000/
  4 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   786.79us    1.11ms  11.73ms   84.24%
    Req/Sec    50.98k     3.97k   86.53k    91.50%
  1018820 requests in 5.03s, 526.62MB read
Requests/sec: 202743.27
Transfer/sec:    104.80MB

```

- Multi-threaded (connection close)
```
  worker #0 ready
  worker #2 ready
💥 powpow accepting on 0.0.0.0:9000 with 4 workers (SO_REUSEPORT)
  worker #3 ready
  worker #1 ready
Running 5s test @ http://127.0.0.1:9000/
  4 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     1.31ms    0.95ms  15.44ms   67.66%
    Req/Sec    13.24k   614.80    14.91k    81.50%
  264133 requests in 5.01s, 135.27MB read
Requests/sec:  52687.29
Transfer/sec:     26.98MB

```

### Security

Need to take input validation and DoS-resistance seriously. A dedicated security
audit was performed; the high-priority findings it produced are fixed and
covered by regression tests in [`tests/test_security.nim`](tests/test_security.nim).

**Hardened by default:**
- **Idle / read timeouts** — `readTimeoutMs` and `keepAliveMs` are now enforced
  per connection, closing slowloris and idle keep-alive connections that never
  complete their requests.
- **Bounded header buffering** — an oversized header packet is rejected
  (`414`/`431`) *before* the parser grows its buffer to the packet size, so a
  hostile multi-megabyte header block cannot force a matching allocation.
- **Overflow-safe `Content-Length`** — adversarial values (e.g. `2^63`) are
  rejected instead of crashing or wrapping to a negative length, closing a
  request-smuggling/desync primitive.
- **Bounded streaming uploads** — streamed bodies (temp-file and multipart) are
  capped even with `maxBodySize = 0`, and size-limit violations reply `413`
  instead of raising an unhandled exception.
- **WebSocket frame caps** — an absolute frame-size cap applies even in
  `maxFrameSize = 0` ("unlimited") mode, preventing OOM on hostile 64-bit
  lengths and unbounded fragmented-message assembly.
- **Stack-safe response headers** — `sendFile`/`streamFile` header assembly
  grows safely; long filenames or custom headers can no longer overflow a fixed
  stack buffer.
- **Path-confusion-proof static serving** — `serveFile` requires a real path
  boundary under `fsRoot`, so a sibling directory sharing the prefix
  (e.g. `/var/www2`) can no longer be served.
- **Symlink-safe static serving** — served paths are resolved with `realpath`
  and must stay under `fsRoot`; a symlink inside the root pointing outside is
  rejected with `403`.
- **Multipart per-file limits** — `server.maxFileSize` bounds a single uploaded
  part independently of the total body cap (violations reply `413`).
- **WebSocket handshake hardening** — `handshakeTimeoutMs` closes connections
  that never complete the HTTP→WebSocket upgrade, and `maxHandshakeSessions`
  caps in-flight handshakes (handshake-stall DoS defense).
- **Strict header parsing** — obs-fold / leading-whitespace header lines are
  rejected (`400`), and `Transfer-Encoding` enables chunked framing only when
  the final token is exactly `chunked`.
- **Thread-safe rate limiter** — `RateLimiter` guards its bucket table with a
  lock, so it can be shared across multi-threaded server workers.
- **TLS reflection guards** — the TLS `sendv` coalesce buffer is capped
  (1 MB), so an attacker-controlled response echoed over TLS cannot force an
  arbitrarily large allocation.

### Recommended production configuration

For publicly reachable endpoints, set explicit caps instead of relying on the
defaults (the `maxBodySize = 0` backstop is `MaxStreamBodySize`:

```nim
let server = newHttpServer(loop)
server.maxBodySize    = 50 * 1024 * 1024      # 50 MB total request body
server.maxStreamBodySize = 64 * 1024 * 1024   # hard cap even when maxBodySize=0
server.maxFileSize    = 10 * 1024 * 1024      # 10 MB per uploaded file
server.maxFieldSize   = 64 * 1024             # 64 KB per text field
server.maxConnections = 4096                  # cap concurrent connections
server.maxPipelineDepth = 4                   # cap pipelined requests
server.readTimeoutMs  = 5_000                 # slowloris / partial-request close
server.setKeepAliveTimeout(5_000)             # idle keep-alive close
```

The same caps apply to the standalone `WsServer` via `maxFrameSize`,
`handshakeTimeoutMs`, `maxHandshakeSessions`, and (once enabled) a
post-upgrade `idleTimeoutMs`.

[Smuggler](https://github.com/openpeeps/smuggler) is a grammar-based
HTTP/1.x request-smuggling fuzzer built for this library: it generates and
mutates requests from a context-free grammar, detects CL/TE desyncs with an
in-process oracle, and drives live servers with the two-request
response-pairing technique.

### Security roadmap

- [ ] Coverage-guided fuzzing of the HTTP / WebSocket / multipart parsers
      (libFuzzer & nim-drchaos adapters in `smuggler`)
- [ ] ASan/UBSan sanitizer build wired into CI
- [ ] Stream body bytes before first-packet buffering (avoid peak RAM on large
      single-packet uploads)
- [x] Multipart per-file size limits wired to server configuration
- [x] Symlink-safe static serving (realpath checks)
- [x] WebSocket handshake timeout and handshake-session bound
- [x] Rate-limiter thread-safety in multi-threaded mode
- [x] Strict header parsing (reject obs-fold/leading-whitespace header lines,
      non-`chunked` `Transfer-Encoding` tokens)
- [x] Response-reflection guards for large attacker-controlled echoes under TLS

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/openpeeps/powpow/issues)
- 👋 Wanna help? [Fork it!](https://github.com/openpeeps/powpow/fork)

|  |  |
|---|---|
| <a href="https://opencode.ai/go?ref=BHMEEK48QX"><img src="https://github.com/openpeeps/pistachio/blob/main/.github/opencode.png" alt="OpenCode"></a> | Switch to **Open-Source LLMs** via OpenCode GO, choosing from a variety of powerful models such as DeepSeek, Qwen, Kimi, GLM-5, MiniMax, MiMo. 🍕 [Use our referral link to get started!](https://opencode.ai/go?ref=BHMEEK48QX)|

### 🎩 License
MIT license. [Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright OpenPeeps & Contributors &mdash; All rights reserved.
