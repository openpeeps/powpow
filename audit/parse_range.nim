## audit/parse_range.nim
##
## Round-2: parseRange must reject trailing garbage / multi-range instead of
## silently truncating, while tolerating trailing OWS.

import powpow/proto/httpserver
import std/unittest

suite "parseRange strictness":

  test "valid single ranges parse":
    check parseRange("bytes=0-5", 100).ok
    check parseRange("bytes=0-5 ", 100).ok
    check parseRange("bytes=0-5\t", 100).ok
    check parseRange("bytes=5-", 100).ok
    check parseRange("bytes=-5", 100).ok

  test "trailing garbage and multi-range rejected":
    check not parseRange("bytes=0-5x", 100).ok
    check not parseRange("bytes=0-5garbage", 100).ok
    check not parseRange("bytes=0-1,3-4", 100).ok
    check not parseRange("bytes=0- 5", 100).ok
