---
title: Performance
description: "powpow's performance mechanisms — SIMD, pooling, zero-copy, timer wheel — plus the dummy benchmarks."
keywords: ["powpow", "performance", "benchmarks", "simd", "zero-copy"]
---

# Performance

powpow is built to be fast. Its design goals map to concrete mechanisms, most of
them visible in the source and the benchmark numbers below.

## Mechanisms

- **Zero-copy parsing.** The HTTP parser materializes request fields lazily from
  byte offsets — nothing is copied until you ask for it.
  ([parser](http/parser.md))
- **Zero-copy file transmission.** Files are sent with `sendfile`
  (`TransmitFile` on Windows) — no userspace round-trip. Under the io_uring
  backend they go through `IORING_OP_SPLICE` (file → pipe → socket), which is
  equally copy-free. ([static files](http/static-files.md))
- **Zero-copy sends (io_uring).** `IORING_OP_SEND_ZC` pins the buffer once and
  reports a `IORING_CQE_F_NOTIF` before the pages may be reused; registered
  buffers (`-d:powpowSendZcFixed`) remove the per-op pinning entirely.
  ([io_uring](io_uring.md))
- **SIMD scanning.** SSE2-accelerated CRLF / CRLFCRLF detection with a scalar
  fallback (`proto/simdscan.nim`). `findDoubleCRLF` locates the header terminator
  in a few instructions per 16 bytes.
- **Pointer-based fd dispatch.** No hash-table lookups on the hot path;
  generation-counter stale-event detection; dead-watcher sweep.
- **4-level hierarchical timer wheel.** O(1) timer insert/fire/cancel.
  ([event loop](core/event-loop.md))
- **Object pooling.** Connections, parsers, responses and WebSockets are pooled
  and reused; `newHttpServer` prewarms the pools by default
  (`populatePools`, pool size 256).
- **Write buffering + corking.** TCP writes are buffered and corked
  (`TCP_CORK`/`TCP_NOPUSH`), flushed when the connection is writable.
- **Scatter-gather writes.** `sendv` batches header + body into one `writev`.
- **`SO_REUSEPORT`** distributes connections across one loop per CPU core with
  zero cross-thread communication. ([concurrency](concurrency.md))
- **Edge-triggered I/O** on kqueue/epoll.

## io_uring: what to expect

On Linux powpow ships an opt-in **io_uring** backend (submission-based, enabled
with `--features:io_uring` / `-d:powpowIoUring`) alongside the default epoll
backend. It is built directly on `io_uring_setup`/`io_uring_enter` (no liburing
dependency) and works on kernels ≥ 5.6.

It helps to be precise about where io_uring wins and where it does not.

### Why io_uring is not dramatically faster on plain HTTP/1.x

io_uring's headline advantage is **parallelism**: many independent operations
(files, sockets, storage, buffered I/O) can be submitted in a batch and executed
asynchronously, with completions reaped in one pass. But HTTP/1.x over TCP is
**serialized per connection** — at any moment a connection has at most one
`RECV` and one `SEND` in flight, because a client sends a request and waits for
the response before the next request. There is nothing for io_uring to parallelize
in that single request/response cycle, so on a small number of connections the
two backends do the same amount of work and epoll's lower per-op overhead can
keep it at or near parity.

The upshot: on a **single-threaded keep-alive `/hello`** workload, don't expect
io_uring to beat epoll by a large margin. That benchmark is bounded by TCP
serialization and parsing, not by the I/O backend.

### Where io_uring does help

The advantage shows up as **concurrency scales** and for **non-socket I/O**:

- **High connection counts** — one `io_uring_enter` submits ops across many
  connections at once (powpow keeps several `ACCEPT` ops in flight per
  listener), and completions are reaped in a tight CQ loop. At thousands of
  concurrent connections this reduces syscall overhead versus epoll's
  per-event `recv`/`send` round trips.
- **`Connection: close` churn** — the accept/connect/read/write/close lifecycle
  is syscall-heavy, which is where batching and fixed-file registration pay off.
- **Zero-copy static file serving** — `IORING_OP_SENDFILE` (kernel ≥ 6.0) streams
  a file to the socket with no userspace round trip; older kernels fall back to a
  `READ` + `SEND` pump.

### Runtime-gated fast paths

To stay correct on kernels ≥ 5.6 while still using newer features where present,
fast paths are enabled at runtime based on the detected kernel version:

- `IORING_OP_SENDFILE` — kernel ≥ 6.0 (fallback to READ + SEND below).
- Multishot `ACCEPT` — kernel ≥ 6.0 (fallback to a batch of one-shot accepts).
- Provided-buffer multishot `RECV` — opt-in via `-d:powpowBufferSelect`,
  kernel ≥ 5.19 (falls back to the one-shot RECV path).

A few build-time switches exist for A/B testing the implementation choices:
`-d:powpowNoFixedFiles` (skip the per-connection fixed-file table syscalls),
`-d:powpowNoSendfile`, `-d:powpowNoMultishotAccept`.

### Looking ahead: HTTP/2 and HTTP/3

io_uring's parallelism becomes genuinely relevant with protocols that multiplex
many independent streams over a single connection:

- **HTTP/2** multiplexes requests over one TCP connection, so multiple reads and
  writes for independent streams are in flight at once — a much better fit for
  io_uring than HTTP/1.x. powpow plans an HTTP/2 implementation soon.
- **HTTP/3 (QUIC)** decouples streams from TCP entirely, running over UDP with
  its own framing — the clearest case where io_uring's completion-driven model
  can meaningfully reduce per-stream overhead.

For today's HTTP/1.x, treat the io_uring backend as a way to reach epoll parity
with headroom at scale and zero-copy file serving, rather than a guaranteed
speed-up on every benchmark.

## Dummy benchmarks

From the README (wrk-based, run via the `bench.yml` GitHub Action). PowPow is
the **#1 ranked HTTP server** on the
[Web Framework Benchmarks](https://web-frameworks-benchmark.netlify.app/result).

### Single-threaded (keep-alive)

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

### Single-threaded (connection close)

```
Running 5s test @ http://127.0.0.1:9000/
  4 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     1.97ms  202.12us   4.22ms   80.09%
    Req/Sec     9.13k     3.62k   18.16k    71.43%
  184469 requests in 5.10s, 103.62MB read
Requests/sec:  36174.22
Transfer/sec:     20.32MB
```

### Multi-threaded (keep-alive)

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

### Multi-threaded (connection close)

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

## Benchmarking it yourself

```bash
nim c -d:release examples/httpserver.nim
wrk -t4 -c100 -d5s http://127.0.0.1:9000/
wrk -t4 -c100 -d5s -H "Connection: close" http://127.0.0.1:9000/
```

There is also a dedicated loop benchmark: `tests/test_bench_event_loop.nim`.

## API reference

- [SIMD scanning API](api/simdscan.md)
- [event loop](core/event-loop.md), [static files](http/static-files.md),
  [concurrency](concurrency.md)
