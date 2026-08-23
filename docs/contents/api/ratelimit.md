---
title: ratelimit
description: "The RateLimiter API: newRateLimiter, newMultiRateLimiter, allow, check and close."
keywords: ["powpow", "api", "ratelimit", "rate limiting", "multi-window"]
---

# ratelimit

Sliding-window rate limiter on the event loop, with single- or multi-window
limits. Source: `src/powpow/proto/ratelimit.nim`. Guide:
[Rate limiting](../http/rate-limiting.md).

## Types

```nim
RateLimiter* = ref object
  loop*: Loop

WindowLimit* = tuple[maxRequests: int, windowMs: int]
```

## Procs

```nim
proc newMultiRateLimiter*(loop: Loop; limits: openArray[WindowLimit];
                          enableCleanup = true): RateLimiter
proc newRateLimiter*(loop: Loop; maxRequests: int; windowMs: int;
                     enableCleanup = true): RateLimiter  # single-window shorthand
proc close*(rl: RateLimiter)
proc allow*(rl: RateLimiter; ip: string): bool
proc check*(rl: RateLimiter; req: HttpRequest; res: HttpResponse): bool {.inline.}
```

With multiple windows, `allow` verifies every window before incrementing any —
a request rejected by one quota is not counted against the others. Windows with
`maxRequests <= 0` are unlimited.

`check` sends a `429` response when the request is over the budget and returns
`false`.

## Related

- [httpserver](httpserver.md) — used inside handlers
- [security](../security.md) — thread-safety notes
