## audit/udp_empty_send.nim
##
## Round-2: sending an empty UDP payload must not read `data[0]` of an empty
## seq (previously `unsafeAddr data[0]` was used before the guard).

import powpow
import std/unittest

suite "UDP empty payload":

  test "empty send/sendTo return 0 without crashing":
    let loop = newLoop()
    let sock = loop.bindUdp("127.0.0.1", 19920,
      onData = proc(sender: common.Sockaddr_storage; data: openArray[byte]) = discard)
    check sock.send(newSeq[byte](0)) == 0
    check sock.send("") == 0
    check sock.sendTo(newSeq[byte](0), "127.0.0.1", 19921) == 0
    check sock.sendTo("", "127.0.0.1", 19921) == 0
    sock.close()
    loop.close()
