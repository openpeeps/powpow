## audit/dns_hostile.nim
##
## DNS hostile-input pins: malformed resolv.conf content, hostile nameserver
## literals, and attacker-crafted wire responses must fail closed — never
## crash (Defect), hang, or poison the cache.

import powpow
import std/[unittest, strutils]

# ── resolv.conf hostile content (pure function, no loop) ─────────────────────

suite "DNS resolv.conf hostile content":

  test "garbage nameservers are skipped, valid ones kept":
    let r = parseResolvConfContent("""
# comment
; another comment
nameserver not-an-ip
nameserver 8.8.8.8
nameserver 1.2.3.4%eth0
nameserver
nameserver fe80::1%7
bogus directive here
""")
    check r.nameservers.len == 2

  test "search list capped at 6, last search/domain wins":
    let r = parseResolvConfContent(
      "search a.com b.com c.com d.com e.com f.com g.com h.com\n")
    check r.search.len == 6
    let r2 = parseResolvConfContent("search a.com b.com\ndomain c.com\n")
    check r2.search == @["c.com"]

  test "out-of-range options ignored, defaults kept":
    let r = parseResolvConfContent(
      "options ndots:99 timeout:abc attempts:-2\n")
    check r.ndots == 1
    check r.timeoutMs == 5_000
    check r.attempts == 2

  test "empty content yields defaults without crashing":
    let r = parseResolvConfContent("")
    check r.nameservers.len == 0
    check r.search.len == 0
    check r.ndots == 1

# ── nameserver literal hostile ───────────────────────────────────────────────

suite "DNS nameserver literal hostile":

  test "valid literals parse":
    discard parseNameserverIp("8.8.8.8")
    discard parseNameserverIp("2001:4860:4860::8888")
    let scoped = parseNameserverIp("fe80::1%3")
    check scoped.scope == 3

  test "hostile literals raise NetError, never a Defect":
    expect NetError:
      discard parseNameserverIp("")
    expect NetError:
      discard parseNameserverIp("garbage")
    expect NetError:
      discard parseNameserverIp("fe80::1%")
    expect NetError:
      discard parseNameserverIp("1.2.3.4%eth0")

# ── hostile wire responses (offline fake responder) ──────────────────────────

type
  HostileMode = enum
    hmPtrLoop    ## answer NAME is a compression pointer to itself
    hmAnCount    ## ANCOUNT=64 with a single real answer + garbage
    hmWrongTxid  ## valid reply but for a different query id
    hmTtlMax     ## valid A answer with TTL 0xFFFFFFFF
    hmTruncated  ## 12-byte header claiming a question, no question bytes

  HostileDns = ref object
    sock: UdpSocket
    mode: HostileMode

proc dnsQuestion(id: uint16; qname: string; qtype: uint16;
                 ancount: int): seq[byte] =
  result = newSeq[byte](12)
  result[0] = byte((id shr 8) and 0xFF)
  result[1] = byte(id and 0xFF)
  result[2] = 0x81
  result[3] = 0x80
  result[4] = 0; result[5] = 1
  result[6] = byte((ancount shr 8) and 0xFF)
  result[7] = byte(ancount and 0xFF)
  result[8] = 0; result[9] = 0
  result[10] = 0; result[11] = 0
  for label in qname.split('.'):
    if label.len > 0:
      result.add(label.len.uint8)
      for ch in label:
        result.add(ch.uint8)
  result.add(0)
  result.add(byte((qtype shr 8) and 0xFF)); result.add(byte(qtype and 0xFF))
  result.add(0); result.add(1)

proc decodeQname(msg: seq[byte]): tuple[name: string, pos: int] =
  var pos = 12
  var name = ""
  while pos < msg.len:
    let ln = msg[pos].int
    if ln == 0:
      return (name, pos + 1)
    if pos + 1 + ln > msg.len:
      return (name, pos + 1)
    if name.len > 0:
      name.add('.')
    for i in 1 .. ln:
      name.add(char(msg[pos + i]))
    pos += 1 + ln
  (name, pos)

proc startHostileDns(loop: Loop; port: int; mode: HostileMode): HostileDns =
  loop.setSearchDomains(@[])
  let h = HostileDns(mode: mode)
  h.sock = loop.bindUdp("127.0.0.1", port,
    onData = proc(sender: common.Sockaddr_storage; data: openArray[byte]) =
      if data.len < 12:
        return
      let id = (uint16(data[0]) shl 8) or data[1]
      let (name, pos) = decodeQname(@data)
      var qtype: uint16 = 1
      if pos + 4 <= data.len:
        qtype = (uint16(data[pos]) shl 8) or data[pos + 1]
      case h.mode
      of hmPtrLoop:
        var resp = dnsQuestion(id, name, qtype, 1)
        let self = resp.len
        resp.add(0xC0); resp.add(byte(self and 0xFF))
        discard h.sock.sendTo(resp, sender)
      of hmAnCount:
        var resp = dnsQuestion(id, name, qtype, 64)
        resp.add(0xC0); resp.add(0x0C)
        resp.add(0); resp.add(1)
        resp.add(0); resp.add(1)
        resp.add(0); resp.add(0); resp.add(0); resp.add(60)
        resp.add(0); resp.add(4)
        resp.add(10); resp.add(0); resp.add(0); resp.add(7)
        resp.add(0xFF)
        discard h.sock.sendTo(resp, sender)
      of hmWrongTxid:
        let bad = (id + 1) and 0xFFFF
        discard h.sock.sendTo(
          dnsQuestion(bad.uint16, name, qtype, 0), sender)
      of hmTtlMax:
        if qtype == 1:
          var resp = dnsQuestion(id, name, qtype, 1)
          resp.add(0xC0); resp.add(0x0C)
          resp.add(0); resp.add(1)
          resp.add(0); resp.add(1)
          resp.add(0xFF); resp.add(0xFF); resp.add(0xFF); resp.add(0xFF)
          resp.add(0); resp.add(4)
          resp.add(10); resp.add(0); resp.add(0); resp.add(9)
          discard h.sock.sendTo(resp, sender)
        else:
          discard h.sock.sendTo(
            dnsQuestion(id, name, qtype, 0), sender)
      of hmTruncated:
        var resp = newSeq[byte](12)
        resp[0] = byte((id shr 8) and 0xFF)
        resp[1] = byte(id and 0xFF)
        resp[2] = 0x81; resp[3] = 0x80
        resp[4] = 0; resp[5] = 1
        discard h.sock.sendTo(resp, sender)
  )
  result = h

proc pollUntil(loop: Loop; pred: proc(): bool; maxPolls: int): int =
  result = 0
  while not pred() and result < maxPolls:
    loop.poll(1)
    inc result

suite "DNS hostile wire":

  test "compression-pointer loop fails closed, no hang":
    let loop = newLoop()
    loop.setDnsServers([("127.0.0.1", 39711)])
    loop.configureDns(200, 2)
    let h = startHostileDns(loop, 39711, hmPtrLoop)
    var errMsg = ""
    var called = false
    loop.resolveAddr("ptrloop.example", 80, SOCK_STREAM,
      proc(addrs: seq[Sockaddr_storage]; err: string) =
        errMsg = err
        called = true
    )
    discard pollUntil(loop, proc(): bool = called, 20_000)
    check called
    check errMsg.len > 0
    h.sock.close()
    loop.close()

  test "inflated ANCOUNT fails closed, no over-read":
    let loop = newLoop()
    loop.setDnsServers([("127.0.0.1", 39712)])
    loop.configureDns(200, 2)
    let h = startHostileDns(loop, 39712, hmAnCount)
    var errMsg = ""
    var called = false
    loop.resolveAddr("ancount.example", 80, SOCK_STREAM,
      proc(addrs: seq[Sockaddr_storage]; err: string) =
        errMsg = err
        called = true
    )
    discard pollUntil(loop, proc(): bool = called, 20_000)
    check called
    check errMsg.len > 0
    h.sock.close()
    loop.close()

  test "wrong query id is ignored, lookup times out cleanly":
    let loop = newLoop()
    loop.setDnsServers([("127.0.0.1", 39713)])
    loop.configureDns(60, 1)
    let h = startHostileDns(loop, 39713, hmWrongTxid)
    var errMsg = ""
    var called = false
    loop.resolveAddr("spoof.example", 80, SOCK_STREAM,
      proc(addrs: seq[Sockaddr_storage]; err: string) =
        errMsg = err
        called = true
    )
    discard pollUntil(loop, proc(): bool = called, 20_000)
    check called
    check errMsg.contains("timed out")
    h.sock.close()
    loop.close()

  test "max TTL resolves without crash or cache poisoning":
    let loop = newLoop()
    loop.setDnsServers([("127.0.0.1", 39714)])
    loop.configureDns(200, 2)
    let h = startHostileDns(loop, 39714, hmTtlMax)
    var got: seq[Sockaddr_storage] = @[]
    var errMsg = ""
    var called = false
    loop.resolveAddr("ttlmax.example", 80, SOCK_STREAM,
      proc(addrs: seq[Sockaddr_storage]; err: string) =
        got = addrs
        errMsg = err
        called = true
    )
    discard pollUntil(loop, proc(): bool = called, 20_000)
    check called
    check errMsg.len == 0
    check got.len == 1
    called = false
    loop.resolveAddr("ttlmax.example", 80, SOCK_STREAM,
      proc(addrs: seq[Sockaddr_storage]; err: string) =
        got = addrs
        errMsg = err
        called = true
    )
    discard pollUntil(loop, proc(): bool = called, 20_000)
    check called
    check errMsg.len == 0
    check got.len == 1
    h.sock.close()
    loop.close()

  test "truncated question section fails closed":
    let loop = newLoop()
    loop.setDnsServers([("127.0.0.1", 39715)])
    loop.configureDns(200, 2)
    let h = startHostileDns(loop, 39715, hmTruncated)
    var errMsg = ""
    var called = false
    loop.resolveAddr("short.example", 80, SOCK_STREAM,
      proc(addrs: seq[Sockaddr_storage]; err: string) =
        errMsg = err
        called = true
    )
    discard pollUntil(loop, proc(): bool = called, 20_000)
    check called
    check errMsg.len > 0
    h.sock.close()
    loop.close()
