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
> 💥 PowPow is experimental and under active development. The API may change without deprecation. If you are looking for a more stable and mature library, consider using [supranim](https://github.com/supranim/supranim) instead (based on LibEvent). 💥

> [!WARNING]
> 💥 This library is not production-ready and may contain bugs and security vulnerabilities. It has been tested on Linux and macOS, but may not work on all platforms. **Use it, test it, and do not hesitate to report any issues you find!** 💥 

## Examples
Check examples in the `examples/` directory, or see the [API reference](https://openpeeps.github.io/powpow) for more details.


## Dummy Benchmarks
**Pow Pow is the #1 fastest HTTP server** from [Web Framework Benchmarks](https://web-frameworks-benchmark.netlify.app/result). Here you can find some wrk-based benchmarks I manually ran via Github Actions (see [latest results here](https://github.com/openpeeps/powpow/actions/runs/27644007710/job/81751133711))

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

|  |  |
|---|---|
| <a href="https://opencode.ai/go?ref=BHMEEK48QX"><img src="https://github.com/openpeeps/pistachio/blob/main/.github/opencode.png" alt="OpenCode"></a> | Switch to **Open-Source LLMs** via OpenCode GO, choosing from a variety of powerful models such as DeepSeek, Qwen, Kimi, GLM-5, MiniMax, MiMo. 🍕 [Use our referral link to get started!](https://opencode.ai/go?ref=BHMEEK48QX)|

### 🎩 License
LGPLv3 license. [Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright OpenPeeps & Contributors &mdash; All rights reserved.
