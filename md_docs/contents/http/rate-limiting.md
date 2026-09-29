---
title: Rate limiting
description: "The sliding-window RateLimiter for per-IP request budgets, safe to share across threads."
keywords: ["powpow", "rate limit", "ratelimit", "throttling", "http"]
---

# Rate limiting

`proto/ratelimit.nim` provides a sliding-window rate limiter keyed by client IP,
integrated with the event loop and safe to share across threads.

Runnable example: [`examples/ratelimit_server.nim`](../../examples/ratelimit_server.nim).

## Creating a limiter

```nim
let rl = newRateLimiter(loop, maxRequests = 5, windowMs = 10_000)
```

Sliding window: each IP may make up to `maxRequests` requests per `windowMs`.
`enableCleanup = true` (default) sweeps idle buckets. `rl.close()` frees the
limiter's timers.

## Multi-window limits

One limiter can enforce several time windows at once — e.g. a per-IP hourly
quota *and* a daily quota:

```nim
let rl = newMultiRateLimiter(loop, [
  (maxRequests: 100, windowMs: 3_600_000),   # 100/hour
  (maxRequests: 1_000, windowMs: 86_400_000) # 1000/day
])
```

Every window is verified before any is incremented (two-phase `allow`), so a
request rejected by the daily quota is not also counted against the hourly.
Entries with `maxRequests <= 0` are unlimited. `newRateLimiter` is shorthand
for a single-window `newMultiRateLimiter`.

## Using it in a handler

```nim
proc handler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  if not rl.check(req, res):      # 429 already sent when false
    return
  res.send("within the budget")
```

`check(req, res)` combines `allow(getClientIp(req))` with sending a `429` when
rejected — the convenient form.

For non-HTTP contexts, use the raw form:

```nim
if rl.allow(clientIp):
  # proceed
else:
  # rejected — this window is exhausted
```

## Thread safety

`RateLimiter` guards its bucket table with a lock, so one limiter can be shared
across the worker threads of a multi-threaded server. Covered by
`tests/test_ratelimit_threads.nim` (`nimble testThreads`). See
[concurrency](../concurrency.md).

## API reference

Full signatures: [rate limiter API](../api/ratelimit.md). Related:
[server](server.md), [security](../security.md).
