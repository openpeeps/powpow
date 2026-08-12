---
title: ratelimit
description: "The RateLimiter API: newRateLimiter, allow, check and close."
keywords: ["powpow", "api", "ratelimit", "rate limiting"]
---

# ratelimit

Sliding-window rate limiter on the event loop. Source:
`src/powpow/proto/ratelimit.nim`. Guide: [Rate limiting](../http/rate-limiting.md).

## Type

```nim
RateLimiter* = ref object
  loop*: Loop
```

## Procs

```nim
proc newRateLimiter*(loop: Loop; maxRequests: int; windowMs: int;
                     enableCleanup = true): RateLimiter
proc close*(rl: RateLimiter)
proc allow*(rl: RateLimiter; ip: string): bool
proc check*(rl: RateLimiter; req: HttpRequest; res: HttpResponse): bool {.inline.}
```

`check` sends a `429` response when the request is over the budget and returns
`false`.

## Related

- [httpserver](httpserver.md) — used inside handlers
- [security](../security.md) — thread-safety notes
