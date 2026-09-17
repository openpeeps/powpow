## tests/test_ratelimit_threads.nim — Thread-safety smoke for RateLimiter.
##
## Compile/run with `--threads:on` (see the `testThreads` nimble task). A single
## RateLimiter is hammered from several threads concurrently; without the internal
## lock this would corrupt the bucket table or crash.
##
## Threading discipline (Nim ORC has per-thread GC heaps, so raw sharing of GC
## memory across threads is unsound even with a lock): every key is pre-created
## on the main thread before spawning, and each worker touches only its own
## disjoint key set. Workers therefore never insert (no table growth/rehash
## under contention) and never touch another thread's entries — the shared
## lock itself is still hammered by every operation, which is what this smoke
## test exercises. The limiter object is GC-pinned for the duration.

import std/[unittest, typedthreads]
import ../src/powpow

const
  NumWorkers = 8
  HotHits = 2000
  SpreadKeys = 50

var sharedRl: RateLimiter

proc hotKey(w: int): string = "w" & $w & "/hot"
proc spreadKey(w, i: int): string = "w" & $w & "/k" & $i

proc worker(w: int) {.thread.} =
  {.cast(gcsafe).}:
    for i in 0 ..< HotHits:
      discard sharedRl.allow(hotKey(w))
    for i in 0 ..< SpreadKeys:
      discard sharedRl.allow(spreadKey(w, i))

test "rate limiter survives concurrent access":
  let loop = newLoop()
  let rl = newRateLimiter(loop, maxRequests = 5, windowMs = 60_000,
                          enableCleanup = false)
  sharedRl = rl
  GC_ref(sharedRl)

  # Pre-create every entry single-threaded so workers only ever update
  # existing keys (no inserts, no table growth while contended).
  for w in 0 ..< NumWorkers:
    discard rl.allow(hotKey(w))
    for i in 0 ..< SpreadKeys:
      discard rl.allow(spreadKey(w, i))

  var threads: array[NumWorkers, Thread[int]]
  for w in 0 ..< NumWorkers:
    createThread(threads[w], worker, w)
  for w in 0 ..< NumWorkers:
    joinThread(threads[w])

  GC_unref(sharedRl)

  # The shared table must remain consistent: a brand-new IP is still allowed.
  check rl.allow("fresh-ip") == true
  # Every worker's hot key is over its window limit.
  for w in 0 ..< NumWorkers:
    check rl.allow(hotKey(w)) == false

  rl.close()
  loop.close()

  rl.close()
  loop.close()
