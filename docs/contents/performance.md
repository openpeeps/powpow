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
