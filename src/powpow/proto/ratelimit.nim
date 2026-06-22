# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## Sliding-window rate limiter built on powpow's event loop.
##
## Usage:
##   let server = newHttpServer()
##   let rl = newRateLimiter(server.getLoop(), maxRequests = 100, windowMs = 60_000)
##   server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
##     if not rl.check(req, res): return
##     res.status(Http200).send("Hello!")
##

import std/[tables, monotimes, httpcore]

import ../loop
import ../types
import ./http
import ./httpserver

proc monoMs: int64 = getMonoTime().ticks div 1_000_000

type
  Bucket = tuple[start: int64, count: int]

  RateLimiter* = ref object
    loop*: Loop
    buckets: Table[string, Bucket]
    maxRequests: int
    windowMs: int64
    cleanupTimer: TimerId

proc newRateLimiter*(loop: Loop; maxRequests: int; windowMs: int;
                     enableCleanup = true): RateLimiter =
  ## Create a sliding-window rate limiter. `maxRequests` per `windowMs`
  ## per unique client IP. When `enableCleanup` is true (default), a
  ## periodic timer sweeps stale buckets from memory.
  let rl = RateLimiter(
    loop: loop,
    maxRequests: maxRequests,
    windowMs: windowMs.int64,
    buckets: initTable[string, Bucket](64),
  )
  if enableCleanup and windowMs > 0:
    let sweepMs = windowMs div 2
    rl.cleanupTimer = loop.addInterval(max(sweepMs, 1000)) do (id: int):
      let now = monoMs()
      let maxAge = rl.windowMs * 2
      var stale: seq[string]
      for ip, bucket in rl.buckets:
        if now - bucket.start > maxAge:
          stale.add(ip)
      for ip in stale:
        rl.buckets.del(ip)
  result = rl

proc allow*(rl: RateLimiter; ip: string): bool =
  ## Check if a request from `ip` is allowed. Returns true if within
  ## the rate limit, false if the limit has been exceeded.
  if ip.len == 0 or rl.maxRequests <= 0:
    return true
  let now = monoMs()
  var bucket = rl.buckets.getOrDefault(ip, (now, 0))
  if now - bucket.start > rl.windowMs:
    bucket = (now, 0)
  inc bucket.count
  if bucket.count > rl.maxRequests:
    return false
  rl.buckets[ip] = bucket
  return true

proc check*(rl: RateLimiter; req: HttpRequest; res: HttpResponse): bool {.inline.} =
  if not rl.allow(req.getClientIp()):
    res.sendError(Http429, "Too Many Requests")
    return false
  return true
