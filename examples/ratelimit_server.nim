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
