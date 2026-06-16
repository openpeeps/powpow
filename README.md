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
- **Zero-copy file transmission** using `sendfile` (Unix) and `TransmitFile` (Windows)
- Chunked Request Body support for streaming uploads and large payloads
- Memory-efficient Multipart Form Data parsing and Raw Body handling for file uploads
- SIMD-accelerated parsing and formatting of HTTP messages
- Built on top of `epoll` (Linux), and `kqueue` (BSD, macOS), `IOCP` (Windows)
- Support for edge-triggered and level-triggered event notification
- Support for multiple event loops and multi-threaded applications
- Support for MIME type detection based on file extensions

> [!NOTE]
> 💥 PowPow is experimental and under active development. The API may change without deprecation. If you are looking for a more stable and mature library, consider using [supranim](https://github.com/supranim/supranim) instead (based on LibEvent). 💥

> [!WARNING]
> 💥 This library is not production-ready and may contain bugs and security vulnerabilities. It has been tested on Linux and macOS, but may not work on all platforms. **Use it, test it, and do not hesitate to report any issues you find!** 💥 

## Examples
Check examples in the `examples/` directory, or see the [API reference](https://openpeeps.github.io/powpow) for more details.


## Dummy Benchmarks
Here you can find some wrk-based benchmarks I manually ran via Github Actions (see [latest results here](https://github.com/openpeeps/powpow/actions/runs/27617904105/job/81658449814)).

- Single-threaded (keep-alive)
```
⚡ powpow HTTP server listening on http://localhost:9000
  Press Ctrl+C to stop
Running 10s test @ http://127.0.0.1:9000/
  4 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   263.79us   35.34us   3.29ms   87.34%
    Req/Sec    20.65k    24.97k   69.58k    75.12%
  825176 requests in 10.10s, 426.53MB read
Requests/sec:  81707.97
Transfer/sec:     42.23MB
```

- Single-threaded (connection close)
```
⚡ powpow HTTP server listening on http://localhost:9000
  Press Ctrl+C to stop
Running 10s test @ http://127.0.0.1:9000/
  4 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    40.56us    9.83us   1.34ms   94.74%
    Req/Sec    11.11k     1.63k   11.95k    97.06%
  112745 requests in 10.01s, 57.74MB read
Requests/sec:  11260.56
Transfer/sec:      5.77MB
```

- Multi-threaded (keep-alive)
```
  worker #0 ready
  worker #1 ready
  worker #2 ready
⚡ powpow accepting on 0.0.0.0:9000 with 4 workers (SO_REUSEPORT)
  worker #3 ready
Running 10s test @ http://127.0.0.1:9000/
  4 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   237.70us  444.60us   8.84ms   93.13%
    Req/Sec    34.12k    10.66k   76.39k    72.32%
  1361919 requests in 10.10s, 703.96MB read
Requests/sec: 134853.84
Transfer/sec:     69.70MB
```

- Multi-threaded (connection close)
```
  worker #0 ready
  worker #1 ready
  worker #2 ready
  worker #3 ready
⚡ powpow accepting on 0.0.0.0:9000 with 4 workers (SO_REUSEPORT)
Running 10s test @ http://127.0.0.1:9000/
  4 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    42.20us   29.73us   2.26ms   98.63%
    Req/Sec    10.63k     1.57k   11.99k    95.19%
  109944 requests in 10.10s, 56.30MB read
Requests/sec:  10885.54
Transfer/sec:      5.57MB
```

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/openpeeps/powpow/issues)
- 👋 Wanna help? [Fork it!](https://github.com/openpeeps/powpow/fork)

### 🎩 License
LGPLv3 license. [Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright OpenPeeps & Contributors &mdash; All rights reserved.
