<p align="center">
  <img src="https://github.com/openpeeps/powpow/blob/main/.github/powpow_logo.png" width="80px"><br>
  PowPow 💥  A high-performance, event notification library for Nim
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
- **Zero-copy file transmission** using `sendfile` (Linux) and `TransmitFile` (Windows)
- Chunked Request Body support for streaming uploads and large payloads
- Memory-efficient Multipart Form Data parsing and Raw Body handling for file uploads
- SIMD-accelerated parsing and formatting of HTTP messages
- Built on top of `epoll` (Linux), and `kqueue` (BSD, macOS), `IOCP` (Windows)
- Support for edge-triggered and level-triggered event notification
- Support for multiple event loops and multi-threaded applications

> [!NOTE]
> PowPow is experimental and under active development. The API may change without deprecation. If you are looking for a more stable and mature library, consider using [supranim](https://github.com/supranim/supranim) instead (based on LibEvent).

> [!WARNING]
> This library is not production-ready and may contain bugs and security vulnerabilities. It has been tested on Linux and macOS, but may not work on all platforms.

## Examples
Check examples in the `examples/` directory, or see the [API reference](https://openpeeps.github.io/powpow) for more details.


## Dummy Benchmarks
Here you can find some wrk-based benchmarks I ran on my local machine (Ryzen 5600, 32GB RAM)

- HTTP/1.1 server with 100 concurrent connections and 2 threads, running on single-threaded event loop
```
wrk -t2 -c100 -d5s http://localhost:9000                       
Running 5s test @ http://localhost:9000
  2 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   131.70us   10.77us 477.00us   88.89%
    Req/Sec    70.27k    25.69k   97.40k    53.00%
  698484 requests in 5.00s, 361.04MB read
Requests/sec: 139676.30
Transfer/sec:     72.20MB
```

- HTTP/1.1 server with 100 concurrent connections and 2 threads, running on single-threaded event loop, with `Connection: close` header
```
wrk -t2 -c100 -d5s http://localhost:9000 -H 'Connection: close'
Running 5s test @ http://localhost:9000
  2 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    36.91us  501.25us  47.79ms   99.86%
    Req/Sec    11.62k     2.08k   13.88k    88.46%
  60096 requests in 5.10s, 30.78MB read
Requests/sec:  11781.15
Transfer/sec:      6.03MB
```

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/openpeeps/powpow/issues)
- 👋 Wanna help? [Fork it!](https://github.com/openpeeps/powpow/fork)

### 🎩 License
LGPLv3 license. [Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright OpenPeeps & Contributors &mdash; All rights reserved.
