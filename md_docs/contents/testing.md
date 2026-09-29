---
title: Testing
description: "The powpow test suite: how to run it, the test-suite map, and the smuggler fuzz configs."
keywords: ["powpow", "testing", "tests", "smuggler", "fuzzing"]
---

# Testing

powpow's test suite lives in [`tests/`](../tests/). The security hardening is
regression-tested by `test_security.nim`, malformed requests by
`test_bad_requests.nim`, and the parser is fuzzed by the smuggler integration
suite.

## Running the tests

```bash
nimble test            # the standard suite (nim c -r on the test files)
nimble testThreads     # thread-safety smoke tests (--threads:on)
nimble testSmuggler    # parser fuzzing (requires the smuggler package)
```

Individual tests (they are standalone scripts):

```bash
nim c -r tests/test_http.nim
nim c -r tests/test_loop.nim
nim c -r tests/test_dns.nim
nim c -r tests/test_tls.nim
nim c -r tests/test_security.nim
nim c -r tests/test_bad_requests.nim
```

## Test-suite map

| File | Covers |
|---|---|
| `test_http.nim` | HTTP parser: basic GET, POST body, query string, headers, chunked encoding, keep-alive |
| `test_net.nim` | Transport: TCP server echo, TCP client connect, UDP bind/send/recv |
| `test_loop.nim` | Event loop: timers, intervals, deferred calls, fd eventing, loop stop |
| `test_dns.nim` | Async DNS: synthetic UDP responder, IP-literal fast path, `/etc/hosts`, A/AAAA fallback, NXDOMAIN, timeout, TTL cache, `connect()` integration |
| `test_tls.nim` | TLS: implicit-TLS echo, STARTTLS-style in-place upgrade |
| `test_signal.nim` | Signal/Relay: repeating listeners, multiple emits |
| `test_security.nim` | Security: body size limits, overflow protection, DoS resistance, connection limits, WS frame limits, path traversal |
| `test_bad_requests.nim` | Malformed-request battery (parser + live server): asserts `400`/`505`/`413`/`431` |
| `test_bench_event_loop.nim` | Loop benchmark/stress: timer-wheel throughput, fd-event latency, mixed load, pointer dispatch / zombie sweep / batch limits |
| `test_ratelimit_threads.nim` | `RateLimiter` thread safety (run with `--threads:on`) |
| `test_multipart_streamer.nim` | Streaming multipart: single/incremental feeds, text fields, file uploads, partial boundary spans, edge cases |
| `test_firefox_regression.nim` | Regression: a real Firefox POST (Cookie header) parses correctly |
| `test_findcrlf.nim` | `findDoubleCRLF` on the exact Firefox POST bytes |
| `test_sse2*.nim` | SIMD CRLF detection: positions, negative cases, chunk-boundary and 225-byte curl buffer cases |
| `smuggler_integration.nim` | powpow × smuggler: in-process parser fuzzing (A), two-server differential vs an RFC-strict reference (B), optional live-server CLI fuzzing (C) |

## Fuzz configs

`tests/fuzz/` holds the smuggler grammars:

- `request-line.cfg` — request-line mutation grammar
- `headers.cfg` — header mutation grammar
- `body.cfg` — body mutation grammar

## Related docs

- [Security](security.md) — what the hardening tests enforce
- [Examples index](examples.md) — runnable programs for manual verification
