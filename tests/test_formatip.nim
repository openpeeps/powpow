## formatIp must return numeric IP literals.
##
## Regression: macOS libc getnameinfo() resolves 127.0.0.1 to "localhost"
## even with NI_NUMERICHOST, so consumers depending on getClientIp() (SPF
## evaluation, per-IP rate limiting) received hostnames instead of addresses.

import ../src/powpow/net/common
import ../src/powpow/net/tcp
when not defined(windows):
  import std/posix

when isMainModule:
  proc mkStorage(family: cint): Sockaddr_storage =
    zeroMem(addr result, sizeof(result))
    when defined(windows):
      result.ss_family = family.cushort
    else:
      result.ss_family = TSa_Family(family)

  template rawBytes(sa: Sockaddr_storage): ptr UncheckedArray[byte] =
    cast[ptr UncheckedArray[byte]](unsafeAddr sa)

  block ipv4Loopback:
    var sa = mkStorage(AF_INET)
    sa.rawBytes()[2] = 0x02'u8   # port 587 big-endian
    sa.rawBytes()[3] = 0x4b'u8
    const ip = [127'u8, 0'u8, 0'u8, 1'u8]
    for i in 0 ..< 4:
      sa.rawBytes()[i + 4] = ip[i]
    doAssert formatIp(sa) == "127.0.0.1", formatIp(sa)

  block ipv4Arbitrary:
    var sa = mkStorage(AF_INET)
    const ip = [8'u8, 8'u8, 8'u8, 8'u8]
    for i in 0 ..< 4:
      sa.rawBytes()[i + 4] = ip[i]
    doAssert formatIp(sa) == "8.8.8.8", formatIp(sa)

  block ipv6Loopback:
    var sa = mkStorage(AF_INET6)
    sa.rawBytes()[8 + 15] = 1'u8   # ::1
    doAssert formatIp(sa) == "::1", formatIp(sa)

  block ipv4MappedPresentedAsIpv4:
    var sa = mkStorage(AF_INET6)
    for i in 0 ..< 10:
      sa.rawBytes()[8 + i] = 0'u8
    sa.rawBytes()[8 + 10] = 0xff'u8
    sa.rawBytes()[8 + 11] = 0xff'u8
    sa.rawBytes()[8 + 12] = 192'u8
    sa.rawBytes()[8 + 13] = 168'u8
    sa.rawBytes()[8 + 14] = 1'u8
    sa.rawBytes()[8 + 15] = 5'u8
    doAssert formatIp(sa) == "192.168.1.5", formatIp(sa)

  block unknownFamilyIsEmpty:
    var sa = mkStorage(cint(0))
    doAssert formatIp(sa) == ""

  echo "test_formatip: all assertions passed"
