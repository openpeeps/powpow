## tests/test_ratelimit_threads.nim — Thread-safety smoke for RateLimiter.
##
## Compile/run with `--threads:on` (see the `testThreads` nimble task). A single
## RateLimiter is hammered from several threads concurrently; without the internal
## lock this would corrupt the bucket table or crash.

import std/[unittest, typedthreads]
import ../src/powpow

var sharedPtr: ptr RateLimiter

proc worker() {.thread.} =
  for i in 0 ..< 2000:
    discard sharedPtr[].allow("1.2.3.4")
  for i in 0 ..< 50:
    discard sharedPtr[].allow("10.0.0." & $i)

test "rate limiter survives concurrent access":
  let loop = newLoop()
  let rl = newRateLimiter(loop, maxRequests = 5, windowMs = 60_000,
                          enableCleanup = false)
  sharedPtr = addr rl

  var threads: array[8, Thread[void]]
  for i in 0 ..< 8:
    createThread(threads[i], worker)
  for i in 0 ..< 8:
    joinThread(threads[i])

  # The shared table must remain consistent: a brand-new IP is still allowed.
  check rl.allow("fresh-ip") == true
  # The hot IP is over its window limit.
  check rl.allow("1.2.3.4") == false

  rl.close()
  loop.close()
