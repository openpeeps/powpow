## tests/test_dns.nim — In-loop DNS resolver tests.
##
## Uses a tiny synthetic DNS responder (built on powpow's UDP) so the tests are
## fully offline and deterministic. Covers the IP-literal fast path, /etc/hosts,
## A/AAAA querying with A-fallback, NXDOMAIN, timeout, TTL caching, connect()
## integration, and that the loop stays responsive during resolution.

import ../src/powpow
import std/[unittest, strutils, tables]

# ── Synthetic DNS responder ──────────────────────────────────────────────────

type
  FakeDns = ref object
    sock: UdpSocket
    queries: int
    answers: Table[string, string]   # hostname -> IPv4, or "nx" for NXDOMAIN
    dropHosts: seq[string]

proc decodeName(msg: seq[byte]; start: int): tuple[name: string, next: int] =
  var pos = start
  var name = ""
  while pos < msg.len:
    let len = msg[pos]
    if len == 0:
      return (name, pos + 1)
    if pos + 1 + len.int > msg.len:
      return (name, pos + 1)
    if name.len > 0:
      name.add('.')
    for i in 1 .. len.int:
      name.add(char(msg[pos + i]))
    pos += 1 + len.int
  (name, pos)

proc dnsResponse(id: uint16; qname: string; rcode: int; qtype: uint16;
                 ip: string): seq[byte] =
  result = newSeq[byte](12)
  result[0] = byte((id shr 8) and 0xFF)
  result[1] = byte(id and 0xFF)
  result[2] = 0x81
  result[3] = byte(0x80 or (rcode and 0x0F))
  result[4] = 0; result[5] = 1          # QDCOUNT
  result[6] = 0; result[7] = (if rcode == 0 and ip.len > 0: 1 else: 0)  # ANCOUNT
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
  if ip.len > 0:
    result.add(0xC0); result.add(0x0C)  # pointer to the question name
    result.add(byte((qtype shr 8) and 0xFF)); result.add(byte(qtype and 0xFF))
    result.add(0); result.add(1)        # IN
    result.add(0); result.add(0); result.add(0); result.add(60)  # TTL 60
    if qtype == 28:
      result.add(0); result.add(16)
      for part in ip.split(':'):
        result.add(0); result.add(parseHexInt(part).uint8)
    else:
      result.add(0); result.add(4)
      for part in ip.split('.'):
        result.add(parseInt(part).uint8)

proc startFakeDns(loop: Loop; port: int): FakeDns =
  let fake = FakeDns(
    queries: 0,
    answers: initTable[string, string](),
    dropHosts: @[],
    sock: nil,
  )
  fake.sock = loop.bindUdp("127.0.0.1", port,
    onData = proc(sender: Sockaddr_storage; data: openArray[byte]) =
      inc fake.queries
      if data.len < 12:
        return
      let id = (uint16(data[0]) shl 8) or data[1]
      let (name, pos) = decodeName(@data, 12)
      if name in fake.dropHosts:
        return
      if pos + 4 > data.len:
        return
      let qtype = (uint16(data[pos]) shl 8) or data[pos + 1]
      let ip = fake.answers.getOrDefault(name.toLowerAscii())
      if ip == "nx":
        discard fake.sock.sendTo(
          dnsResponse(id, name, 3, qtype, ""), sender)
      elif ip.len > 0 and qtype == 1:
        # AAAA queries return an empty answer so the resolver falls back to A.
        discard fake.sock.sendTo(
          dnsResponse(id, name, 0, qtype, ip), sender)
      else:
        discard fake.sock.sendTo(
          dnsResponse(id, name, 0, qtype, ""), sender)
  )
  result = fake

proc stopFakeDns(loop: Loop; f: var FakeDns) =
  f.sock.close()

# ── Tests ────────────────────────────────────────────────────────────────────

proc pollUntil(loop: Loop; pred: proc(): bool; maxPolls: int): int =
  result = 0
  while not pred() and result < maxPolls:
    loop.poll(1)
    inc result

test "test_dns_ip_literal_fast_path":
  let loop = newLoop()
  var got: Sockaddr_storage
  var errMsg = ""
  var called = false
  loop.resolveAddrAsync("10.1.2.3", 8080, SOCK_STREAM,
    proc(addrBuf: Sockaddr_storage; err: string) =
      got = addrBuf
      errMsg = err
      called = true
  )
  assert called, "IP literal should resolve synchronously"
  assert errMsg.len == 0, "no error expected, got: " & errMsg
  assert cast[ptr Sockaddr](unsafeAddr got).sa_family == AF_INET.cushort,
    "expected IPv4 family"
  loop.close()

test "test_dns_localhost_via_hosts":
  let loop = newLoop()
  var errMsg = ""
  var family = cint(0)
  var called = false
  loop.resolveAddrAsync("localhost", 80, SOCK_STREAM,
    proc(addrBuf: Sockaddr_storage; err: string) =
      errMsg = err
      family = cast[ptr Sockaddr](unsafeAddr addrBuf).sa_family.cint
      called = true
  )
  assert called, "localhost should resolve from /etc/hosts"
  assert errMsg.len == 0, "no error expected, got: " & errMsg
  assert family == AF_INET.cint or family == AF_INET6.cint,
    "expected an IP family, got " & $family
  loop.close()

test "test_dns_synthetic_a_fallback":
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29981)])
  loop.configureDns(200, 2)
  var fake = startFakeDns(loop, 29981)
  fake.answers["test.example"] = "10.0.0.7"

  var got: Sockaddr_storage
  var errMsg = ""
  var called = false
  loop.resolveAddrAsync("test.example", 5000, SOCK_STREAM,
    proc(addrBuf: Sockaddr_storage; err: string) =
      got = addrBuf
      errMsg = err
      called = true
  )
  discard pollUntil(loop, proc(): bool = called, 20_000)
  assert called, "callback should fire after DNS A fallback"
  assert errMsg.len == 0, "no error expected, got: " & errMsg

  # The AAAA query is answered empty, forcing the A fallback; the A answer
  # 10.0.0.7 must come through in the resolved address.
  var resolved = sockaddrFromIp("10.0.0.7", 5000)
  let got4 = cast[ptr Sockaddr_in](unsafeAddr got)
  let exp4 = cast[ptr Sockaddr_in](unsafeAddr resolved)
  assert cast[ptr Sockaddr](unsafeAddr got).sa_family == AF_INET.cushort
  assert cmpMem(addr got4.sin_addr, addr exp4.sin_addr, 4) == 0,
    "resolved IP mismatch"
  stopFakeDns(loop, fake)
  loop.close()

test "test_dns_nxdomain":
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29982)])
  loop.configureDns(200, 2)
  var fake = startFakeDns(loop, 29982)
  fake.answers["bad.example"] = "nx"

  var errMsg = ""
  var called = false
  loop.resolveAddrAsync("bad.example", 80, SOCK_STREAM,
    proc(addrBuf: Sockaddr_storage; err: string) =
      errMsg = err
      called = true
  )
  discard pollUntil(loop, proc(): bool = called, 20_000)
  assert called, "callback should fire"
  assert errMsg.len > 0, "expected an NXDOMAIN error"
  assert errMsg.contains("not found") or errMsg.contains("nx"),
    "unexpected error: " & errMsg
  stopFakeDns(loop, fake)
  loop.close()

test "test_dns_timeout":
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29983)])
  loop.configureDns(60, 1)
  var fake = startFakeDns(loop, 29983)
  fake.dropHosts = @["drop.example"]

  var errMsg = ""
  var called = false
  loop.resolveAddrAsync("drop.example", 80, SOCK_STREAM,
    proc(addrBuf: Sockaddr_storage; err: string) =
      errMsg = err
      called = true
  )
  discard pollUntil(loop, proc(): bool = called, 20_000)
  assert called, "callback should fire on timeout"
  assert errMsg.len > 0, "expected a timeout error"
  assert errMsg.contains("timed out"), "unexpected error: " & errMsg
  stopFakeDns(loop, fake)
  loop.close()

test "test_dns_cache":
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29984)])
  loop.configureDns(200, 2)
  var fake = startFakeDns(loop, 29984)
  fake.answers["test.example"] = "10.0.0.9"

  var called = false
  loop.resolveAddrAsync("test.example", 80, SOCK_STREAM,
    proc(addrBuf: Sockaddr_storage; err: string) = called = true)
  discard pollUntil(loop, proc(): bool = called, 20_000)
  assert called, "first resolve should complete"
  let queriesAfterFirst = fake.queries
  assert queriesAfterFirst >= 1, "expected at least one query"

  called = false
  loop.resolveAddrAsync("test.example", 80, SOCK_STREAM,
    proc(addrBuf: Sockaddr_storage; err: string) = called = true)
  discard pollUntil(loop, proc(): bool = called, 20_000)
  assert called, "cached resolve should complete"
  assert fake.queries == queriesAfterFirst,
    "cached resolve must not re-query (was " & $fake.queries & ", before " & $queriesAfterFirst & ")"

  stopFakeDns(loop, fake)
  loop.close()

test "test_dns_connect_via_hostname":
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29985)])
  loop.configureDns(300, 2)
  var fake = startFakeDns(loop, 29985)
  fake.answers["myserver.test"] = "127.0.0.1"

  var server: TcpServer
  var echoData: string = ""
  server = newTcpServer(loop,
    onAccept = proc(conn: Connection) = discard,
    onData = proc(conn: Connection, data: openArray[byte]) =
      discard conn.send(data)
  )
  server.listen("127.0.0.1", 29986)

  var connected = false
  var received = ""
  loop.connect("myserver.test", 29986,
    onConnect = proc(conn: Connection) =
      connected = true
      discard conn.send("dns ok")
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      received = cast[string](@data)
      conn.close()
      server.close()
      loop.stop()
    ,
    onError = proc(err: string) = discard,
  )
  loop.run()

  assert connected, "connect via hostname should succeed"
  assert received == "dns ok", "echo mismatch: " & received
  stopFakeDns(loop, fake)
  loop.close()

test "test_dns_loop_not_blocked":
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29987)])
  loop.configureDns(150, 1)
  var fake = startFakeDns(loop, 29987)
  fake.dropHosts = @["slow.example"]

  var ticks = 0
  var errMsg = ""
  var done = false
  loop.resolveAddrAsync("slow.example", 80, SOCK_STREAM,
    proc(addrBuf: Sockaddr_storage; err: string) =
      errMsg = err
      done = true
  )
  discard loop.addInterval(10) do (id: int):
    inc ticks
  discard pollUntil(loop, proc(): bool = done, 20_000)
  assert done, "callback should fire"
  assert ticks > 0,
    "the loop must keep processing timers while DNS is pending (ticks=" & $ticks & ")"
  assert errMsg.len > 0, "expected timeout"
  stopFakeDns(loop, fake)
  loop.close()
