# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## Sliding-window rate limiter built on powpow's event loop.
##
## Supports multiple time windows per limiter — e.g. per-IP hourly + daily
## quotas checked atomically. The two-phase `allow` verifies every window
## before incrementing any, so a message rejected by the daily quota is not
## overcounted against the hourly.
##
## Single-window (backward-compatible):
##   let rl = newRateLimiter(loop, maxRequests = 100, windowMs = 60_000)
##
## Multi-window:
##   let rl = newMultiRateLimiter(loop, [(100, 3_600_000), (1_000, 86_400_000)])

import std/httpcore except HttpMethod
import std/[tables, monotimes, locks]

import ../loop
import ../types
import ./http
import ./httpserver

proc monoMs: int64 {.inline.} = getMonoTime().ticks div 1_000_000

type
  Bucket = tuple[start: int64, count: int]

  WindowLimit* = tuple[maxRequests: int, windowMs: int]

  KeyState = object
    buckets: seq[Bucket]
    lastSeen: int64

  RateLimiter* = ref object
    loop*: Loop
    limits: seq[WindowLimit]
    states: Table[string, KeyState]
    cleanupTimer: TimerId
    lock: Lock   # guards `states` — the limiter may be shared across workers

# ── Constructors ──────────────────────────────────────────────────────────────

proc newMultiRateLimiter*(loop: Loop; limits: openArray[WindowLimit];
                         enableCleanup = true): RateLimiter =
  ## Create a sliding-window rate limiter with one or more time windows.
  ## Each `limit` is `(maxRequests, windowMs)` — entries with `maxRequests`
  ## <= 0 are treated as unlimited (always allowed, never counted).
  let rl = RateLimiter(
    loop: loop,
    limits: @limits,
    states: initTable[string, KeyState](64),
  )
  initLock(rl.lock)
  if enableCleanup and limits.len > 0:
    # find the largest window for the sweep interval
    var maxWindowMs: int64
    for lim in limits:
      if lim.windowMs > maxWindowMs:
        maxWindowMs = lim.windowMs
    if maxWindowMs > 0:
      let sweepMs = maxWindowMs div 2
      rl.cleanupTimer = loop.addInterval(max(sweepMs, 1000)) do (id: int):
        withLock rl.lock:
          let now = monoMs()
          let maxAge = maxWindowMs * 2
          var stale: seq[string]
          for k, s in rl.states:
            if now - s.lastSeen > maxAge:
              stale.add(k)
          for k in stale:
            rl.states.del(k)
  result = rl

proc newRateLimiter*(loop: Loop; maxRequests: int; windowMs: int;
                     enableCleanup = true): RateLimiter =
  ## Single-window convenience constructor (backward-compatible).
  newMultiRateLimiter(loop, [(maxRequests, windowMs)], enableCleanup)

proc close*(rl: RateLimiter) =
  ## Stop the cleanup timer and release the limiter's lock.
  if rl.cleanupTimer != TimerId(0):
    rl.loop.cancelTimer(rl.cleanupTimer)
    rl.cleanupTimer = TimerId(0)
  deinitLock(rl.lock)

# ── Core allow ────────────────────────────────────────────────────────────────

proc allow*(rl: RateLimiter; key: string): bool =
  ## Check whether `key` is allowed across ALL configured windows.  Returns
  ## true only when every non-unlimited window still has capacity; increments
  ## the count atomically on success.  Returns true immediately for empty keys
  ## or when every rule is unlimited (`maxRequests <= 0`).
  if key.len == 0:
    return true
  var allUnlimited = true
  for lim in rl.limits:
    if lim.maxRequests > 0:
      allUnlimited = false
      break
  if allUnlimited:
    return true

  withLock rl.lock:
    let now = monoMs()
    if key notin rl.states:
      rl.states[key] = KeyState(buckets: newSeq[Bucket](rl.limits.len),
                                lastSeen: 0)
    # Borrow the table slot directly and mutate it in place. The previous
    # copy-out/copy-back (`state = t[key]; ...; t[key] = state`) churns the
    # shared payload's refcount on every call; when the limiter is shared
    # across threads that aliasing is a use-after-free hazard (the slot and
    # the copy briefly alias the same payload). In-place mutation performs no
    # refcount operations on shared cells at all — `Bucket` is plain ints —
    # so the lock alone suffices for thread safety.
    let s = addr rl.states.mgetOrPut(key)
    if s.buckets.len != rl.limits.len:
      s.buckets.setLen(rl.limits.len)

    # Phase 1 — verify every window has capacity.
    for i in 0 ..< rl.limits.len:
      let lim = rl.limits[i]
      if lim.maxRequests <= 0:
        continue
      if now - s.buckets[i].start > lim.windowMs:
        s.buckets[i] = (now, 0)
      if s.buckets[i].count >= lim.maxRequests:
        return false          # reject — nothing was incremented

    # Phase 2 — all passed; increment every non-unlimited window.
    for i in 0 ..< rl.limits.len:
      let lim = rl.limits[i]
      if lim.maxRequests <= 0:
        continue
      inc s.buckets[i].count

    s.lastSeen = now
    return true

# ── HTTP convenience ──────────────────────────────────────────────────────────

proc check*(rl: RateLimiter; req: HttpRequest; res: HttpResponse): bool {.inline.} =
  if not rl.allow(req.getClientIp()):
    res.sendError(Http429, "Too Many Requests")
    return false
  return true
