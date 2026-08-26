---
title: Rate limiting
description: "Sliding-window per-IP limiter returning 429 past the budget."
keywords: ["powpow", "example", "ratelimit"]
---

# Rate limiting

Guards a handler with the built-in rate limiter: five requests per ten seconds
per client IP, after which the limiter itself writes the 429 and the handler
short-circuits.

Source: [`examples/ratelimit_server.nim`](../../examples/ratelimit_server.nim)

```nim
## examples/ratelimit_server.nim — Rate limiter demo.
##
## Shows how to rate-limit requests by client IP using the built-in
## sliding-window rate limiter. Run and test with:
##
##   curl http://localhost:9003/            # 200 OK
##   # Send 5+ rapid requests to trigger 429:
##   for i in $(seq 6); do curl -w "\n%{http_code}\n" http://localhost:9003/; done

import ../src/powpow
import std/[httpcore, strutils]

let server = newHttpServer()

# Allow 5 requests per 10 seconds per IP
let rl = newRateLimiter(server.getLoop(), maxRequests = 5, windowMs = 10_000)

proc handler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  {.gcsafe.}:
    if not rl.check(req, res):
      return

    let ip = req.getClientIp()
    res.status(Http200)
       .header("Content-Type", "text/plain; charset=utf-8")
       .send("Hello from $1!" % [ip])

echo "Rate-limited server on http://localhost:9003  (5 req / 10s per IP)"
server.start(handler, Port(9003))
```

## Running

```bash
nim c -r examples/ratelimit_server.nim
```

## Try it

```bash
for i in $(seq 6); do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:9003/; done
```

## How it works

- `newRateLimiter(server.getLoop(), maxRequests = 5, windowMs = 10_000)` binds
  the limiter's cleanup timers to the server's loop.
- `rl.check(req, res)` returns false when the bucket is exhausted; it has
  already sent the 429 response at that point.
- Identity comes from `req.getClientIp()`, respecting proxy headers when
  configured.

Related: [rate limiting guide](../http/rate-limiting.md) and
[API reference](../api/ratelimit.md).
