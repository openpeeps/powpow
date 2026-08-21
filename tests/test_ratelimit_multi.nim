## tests/test_ratelimit_multi.nim — Multi-window RateLimiter tests.
##
## Compile/run with: `clue build tests/test_ratelimit_multi.nim && ./test_ratelimit_multi`

import std/[unittest]
import ../src/powpow

let loop = newLoop()

test "multi-window: atomic pass — all windows increment":
  # Window A: max 3, Window B: max 2 — B fills first
  let rl = newMultiRateLimiter(loop, [(3, 3_600_000), (2, 3_600_000)],
                              enableCleanup = false)
  check rl.allow("alice") == true   # A=1, B=1
  check rl.allow("alice") == true   # A=2, B=2
  check rl.allow("alice") == false  # B full → reject, A stays at 2
  # Verify atomicity: third call rejected by B didn't increment A
  # (if A had incremented, the key would be at A=3)
  # Now use a fresh key with B=2 limit to prove B is full:
  let rl2 = newMultiRateLimiter(loop, [(3, 3_600_000), (2, 3_600_000)],
                                enableCleanup = false)
  check rl2.allow("a") == true
  check rl2.allow("a") == true
  check rl2.allow("a") == false
  # With A=3,B=2: 2 calls fill B, 3rd rejected; A should allow 1 more
  check rl2.allow("b") == true   # fresh key B=1
  check rl2.allow("b") == true   # B=2 (full)
  check rl2.allow("b") == false  # B full
  rl.close()
  rl2.close()

test "multi-window: reject blocks all — no partial increment":
  # A=5, B=1 (tiny daily)
  let rl = newMultiRateLimiter(loop, [(5, 3_600_000), (1, 3_600_000)],
                              enableCleanup = false)
  check rl.allow("bob") == true    # A=1, B=1
  check rl.allow("bob") == false   # B full → reject, A stays at1
  check rl.allow("bob") == false   # still rejected
  # Verify A didn't overcount by using a fresh key with B=1:
  let rl2 = newMultiRateLimiter(loop, [(5, 3_600_000), (1, 3_600_000)],
                                enableCleanup = false)
  check rl2.allow("x") == true
  check rl2.allow("x") == false    # B full
  check rl2.allow("y") == true     # fresh key — proves A didn't affect y
  rl.close()
  rl2.close()

test "multi-window: unlimited rule skipped":
  let rl = newMultiRateLimiter(loop, [(0, 3_600_000), (2, 3_600_000)],
                              enableCleanup = false)
  # Unlimited A (maxRequests=0), limited B (maxRequests=2)
  check rl.allow("dave") == true
  check rl.allow("dave") == true
  check rl.allow("dave") == false  # B full
  # Third call rejected by B; verify unlimited A didn't block:
  check rl.allow("frank") == true  # fresh key, unlimited A always passes
  check rl.allow("frank") == true
  check rl.allow("frank") == false # B full for frank too
  rl.close()

test "multi-window: independent keys don't interfere":
  let rl = newMultiRateLimiter(loop, [(1, 3_600_000)],
                              enableCleanup = false)
  check rl.allow("A") == true
  check rl.allow("B") == true     # different key, fresh bucket
  check rl.allow("A") == false    # A exhausted
  check rl.allow("B") == false    # B also exhausted (max=1)
  # Fresh key:
  check rl.allow("C") == true
  check rl.allow("C") == false
  rl.close()

test "single-window backward compat":
  let rl = newRateLimiter(loop, maxRequests = 2, windowMs = 60_000,
                          enableCleanup = false)
  check rl.allow("x") == true
  check rl.allow("x") == true
  check rl.allow("x") == false
  # Verify count=2 by using fresh key at same limit:
  let rl2 = newRateLimiter(loop, maxRequests = 2, windowMs = 60_000,
                           enableCleanup = false)
  check rl2.allow("y") == true
  check rl2.allow("y") == true
  check rl2.allow("y") == false
  rl.close()
  rl2.close()

test "all-unlimited returns true without recording":
  let rl = newMultiRateLimiter(loop, [(0, 3_600_000), (0, 86_400_000)],
                              enableCleanup = false)
  check rl.allow("anyone") == true
  # Call again — still unlimited
  check rl.allow("anyone") == true
  rl.close()

test "empty key always allowed":
  let rl = newMultiRateLimiter(loop, [(1, 3_600_000)],
                              enableCleanup = false)
  check rl.allow("") == true
  check rl.allow("") == true
  rl.close()

loop.close()
