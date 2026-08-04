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
> 💥 PowPow is now available in [Supranim](https://github.com/supranim/supranim) as a backend. Just switch to `-d:supraNative` when compiling your Supranim app!

> [!WARNING]
> 💥 This library is not production-ready and may contain bugs and security vulnerabilities. It has been tested on Linux and macOS, but may not work on all platforms. **Use it, test it, and do not hesitate to report any issues you find!** 💥 

## Examples
Check examples in the `examples/` directory, or see the [API reference](https://openpeeps.github.io/powpow) for more details.


## Dummy Benchmarks
**Pow Pow is the #1 fastest HTTP server** from [Web Framework Benchmarks](https://web-frameworks-benchmark.netlify.app/result). Find the wrk-based benchmark I manually ran via Github Actions ([see bench.yml](https://github.com/openpeeps/powpow/blob/main/.github/workflows/bench.yml))

- Single-threaded (keep-alive)
```
⚡ powpow HTTP server listening on http://localhost:9000
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
⚡ powpow HTTP server listening on http://localhost:9000
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
⚡ powpow accepting on 0.0.0.0:9000 with 4 workers (SO_REUSEPORT)
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
⚡ powpow accepting on 0.0.0.0:9000 with 4 workers (SO_REUSEPORT)
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

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/openpeeps/powpow/issues)
- 👋 Wanna help? [Fork it!](https://github.com/openpeeps/powpow/fork)

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

**Fuzzing** — [`t-reqs`](https://github.com/openpeeps/treqs) is a grammar-based
HTTP/1.x request-smuggling fuzzer built for this library: it generates and
mutates requests from a context-free grammar, detects CL/TE desyncs with an
in-process oracle, and drives live servers with the two-request
response-pairing technique.

#### Security roadmap

- [ ] Coverage-guided fuzzing of the HTTP / WebSocket / multipart parsers
      (libFuzzer & nim-drchaos adapters in `treqs`)
- [ ] ASan/UBSan sanitizer build wired into CI
- [ ] Stream body bytes before first-packet buffering (avoid peak RAM on large
      single-packet uploads)
- [ ] Multipart per-file size limits wired to server configuration
- [ ] Symlink-safe static serving (realpath checks)
- [ ] WebSocket handshake timeout and handshake-session bound
- [ ] Rate-limiter thread-safety in multi-threaded mode
- [ ] Strict header parsing (reject obs-fold/leading-whitespace header lines,
      non-`chunked` `Transfer-Encoding` tokens)
- [ ] Response-reflection guards for large attacker-controlled echoes under TLS

|  |  |
|---|---|
| <a href="https://opencode.ai/go?ref=BHMEEK48QX"><img src="https://github.com/openpeeps/pistachio/blob/main/.github/opencode.png" alt="OpenCode"></a> | Switch to **Open-Source LLMs** via OpenCode GO, choosing from a variety of powerful models such as DeepSeek, Qwen, Kimi, GLM-5, MiniMax, MiMo. 🍕 [Use our referral link to get started!](https://opencode.ai/go?ref=BHMEEK48QX)|

### 🎩 License
LGPLv3 license. [Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright OpenPeeps & Contributors &mdash; All rights reserved.
