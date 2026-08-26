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
    answers: Table[string, seq[string]]   # hostname -> IPv4 list, or @["nx"]
    txtAnswers: Table[string, seq[string]] # hostname -> TXT record strings
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
                 ips: seq[string]): seq[byte] =
  result = newSeq[byte](12)
  result[0] = byte((id shr 8) and 0xFF)
  result[1] = byte(id and 0xFF)
  result[2] = 0x81
  result[3] = byte(0x80 or (rcode and 0x0F))
  result[4] = 0; result[5] = 1          # QDCOUNT
  result[6] = 0; result[7] = byte(if rcode == 0 and ips.len > 0: ips.len else: 0)  # ANCOUNT
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
  for ip in ips:
    result.add(0xC0); result.add(0x0C)  # pointer to the question name
    result.add(byte((qtype shr 8) and 0xFF)); result.add(byte(qtype and 0xFF))
    result.add(0); result.add(1)        # IN
    result.add(0); result.add(0); result.add(0); result.add(60)  # TTL 60
    if qtype == 28:
      result.add(0); result.add(16)
      for part in ip.split(':'):
        result.add(0); result.add(parseHexInt(part).uint8)
    elif qtype == 16:
      # TXT record: each string is length-prefixed per RFC 1035 §3.3.14
      let txt = ip  # repurpose ips seq as raw TXT strings
      var rdata: seq[byte]
      for ch in txt:
        rdata.add(ch.uint8)
      result.add(byte((rdata.len shr 8) and 0xFF))
      result.add(byte(rdata.len and 0xFF))
      result.add(rdata)
    else:
      result.add(0); result.add(4)
      for part in ip.split('.'):
        result.add(parseInt(part).uint8)

proc startFakeDns(loop: Loop; port: int): FakeDns =
  let fake = FakeDns(
    queries: 0,
    answers: initTable[string, seq[string]](),
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
      let key = name.toLowerAscii()
      if qtype == 16:  # TXT
        if key in fake.answers and fake.answers[key] == @["nx"]:
          discard fake.sock.sendTo(
            dnsResponse(id, name, 3, qtype, @[]), sender)
        else:
          let txts = fake.txtAnswers.getOrDefault(key)
          if txts.len > 0:
            # Return each TXT string as a separate answer RR with proper
            # character-string encoding per RFC 1035 §3.3.14.
            var resp = newSeq[byte](12)
            resp[0] = byte((id shr 8) and 0xFF)
            resp[1] = byte(id and 0xFF)
            resp[2] = 0x81
            resp[3] = 0x80  # NOERROR
            resp[4] = 0; resp[5] = 1          # QDCOUNT
            resp[6] = 0; resp[7] = byte(txts.len)  # ANCOUNT
            resp[8] = 0; resp[9] = 0
            resp[10] = 0; resp[11] = 0
            # question section
            for label in name.split('.'):
              if label.len > 0:
                resp.add(label.len.uint8)
                for ch in label:
                  resp.add(ch.uint8)
            resp.add(0)
            resp.add(0); resp.add(16)  # QTYPE = TXT
            resp.add(0); resp.add(1)   # QCLASS = IN
            # answer section
            for txt in txts:
              resp.add(0xC0); resp.add(0x0C)  # pointer to question name
              resp.add(0); resp.add(16)       # TYPE = TXT
              resp.add(0); resp.add(1)        # CLASS = IN
              resp.add(0); resp.add(0); resp.add(0); resp.add(60)  # TTL 60
              # Each character-string is length-prefixed (max 255 bytes)
              let rdataLen = 1 + txt.len  # 1 byte for the length prefix
              resp.add(byte((rdataLen shr 8) and 0xFF))
              resp.add(byte(rdataLen and 0xFF))
              resp.add(byte(txt.len and 0xFF))  # character-string length
              for ch in txt:
                resp.add(ch.uint8)
            discard fake.sock.sendTo(resp, sender)
          else:
            # NOERROR with no TXT records
            discard fake.sock.sendTo(
              dnsResponse(id, name, 0, qtype, @[]), sender)
      elif key in fake.answers:
        let ips = fake.answers[key]
        if ips == @["nx"]:
          discard fake.sock.sendTo(
            dnsResponse(id, name, 3, qtype, @[]), sender)
        elif ips.len > 0 and qtype == 1:
          # AAAA queries return an empty answer so the resolver falls back to A.
          discard fake.sock.sendTo(
            dnsResponse(id, name, 0, qtype, ips), sender)
        else:
          discard fake.sock.sendTo(
            dnsResponse(id, name, 0, qtype, @[]), sender)
      else:
        discard fake.sock.sendTo(
          dnsResponse(id, name, 0, qtype, @[]), sender)
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
  var got: seq[Sockaddr_storage] = @[]
  var errMsg = ""
  var called = false
  loop.resolveAddrAsync("10.1.2.3", 8080, SOCK_STREAM,
    proc(addrs: seq[Sockaddr_storage]; err: string) =
      got = addrs
      errMsg = err
      called = true
  )
  assert called, "IP literal should resolve synchronously"
  assert errMsg.len == 0, "no error expected, got: " & errMsg
  assert got.len == 1, "expected one address, got " & $got.len
  assert cast[ptr Sockaddr](unsafeAddr got[0]).sa_family == AF_INET.cushort,
    "expected IPv4 family"
  loop.close()

test "test_dns_localhost_via_hosts":
  let loop = newLoop()
  var got: seq[Sockaddr_storage] = @[]
  var errMsg = ""
  var called = false
  loop.resolveAddrAsync("localhost", 80, SOCK_STREAM,
    proc(addrs: seq[Sockaddr_storage]; err: string) =
      got = addrs
      errMsg = err
      called = true
  )
  assert called, "localhost should resolve from /etc/hosts"
  assert errMsg.len == 0, "no error expected, got: " & errMsg
  assert got.len >= 1, "expected at least one address"
  loop.close()

test "test_dns_synthetic_a_fallback":
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29981)])
  loop.configureDns(200, 2)
  var fake = startFakeDns(loop, 29981)
  fake.answers["test.example"] = @["10.0.0.7"]

  var got: seq[Sockaddr_storage] = @[]
  var errMsg = ""
  var called = false
  loop.resolveAddrAsync("test.example", 5000, SOCK_STREAM,
    proc(addrs: seq[Sockaddr_storage]; err: string) =
      got = addrs
      errMsg = err
      called = true
  )
  discard pollUntil(loop, proc(): bool = called, 20_000)
  assert called, "callback should fire after DNS A fallback"
  assert errMsg.len == 0, "no error expected, got: " & errMsg

  # The AAAA query is answered empty, forcing the A fallback; the A answer
  # 10.0.0.7 must come through in the resolved addresses.
  assert got.len == 1, "expected one address, got " & $got.len
  var resolved = sockaddrFromIp("10.0.0.7", 5000)
  let got4 = cast[ptr Sockaddr_in](unsafeAddr got[0])
  let exp4 = cast[ptr Sockaddr_in](unsafeAddr resolved)
  assert cast[ptr Sockaddr](unsafeAddr got[0]).sa_family == AF_INET.cushort
  assert cmpMem(addr got4.sin_addr, addr exp4.sin_addr, 4) == 0,
    "resolved IP mismatch"
  stopFakeDns(loop, fake)
  loop.close()

test "test_dns_nxdomain":
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29982)])
  loop.configureDns(200, 2)
  var fake = startFakeDns(loop, 29982)
  fake.answers["bad.example"] = @["nx"]

  var errMsg = ""
  var called = false
  loop.resolveAddrAsync("bad.example", 80, SOCK_STREAM,
    proc(addrs: seq[Sockaddr_storage]; err: string) =
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
    proc(addrs: seq[Sockaddr_storage]; err: string) =
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
  fake.answers["test.example"] = @["10.0.0.9"]

  var called = false
  loop.resolveAddrAsync("test.example", 80, SOCK_STREAM,
    proc(addrs: seq[Sockaddr_storage]; err: string) = called = true)
  discard pollUntil(loop, proc(): bool = called, 20_000)
  assert called, "first resolve should complete"
  let queriesAfterFirst = fake.queries
  assert queriesAfterFirst >= 1, "expected at least one query"

  called = false
  loop.resolveAddrAsync("test.example", 80, SOCK_STREAM,
    proc(addrs: seq[Sockaddr_storage]; err: string) = called = true)
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
  fake.answers["myserver.test"] = @["127.0.0.1"]

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
    onError = proc(err: string) =
      # A stalled resolution/connect must not hang `loop.run()` forever.
      loop.stop()
    ,
  )
  # Safety timeout: fail the test cleanly instead of hanging if DNS or the
  # connect never completes.
  discard loop.addTimer(5000) do (id: int):
    loop.stop()
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
    proc(addrs: seq[Sockaddr_storage]; err: string) =
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

test "test_dns_multi_record":
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29988)])
  loop.configureDns(200, 2)
  var fake = startFakeDns(loop, 29988)
  fake.answers["multi.example"] = @["10.1.0.1", "10.1.0.2"]

  var got: seq[Sockaddr_storage] = @[]
  var errMsg = ""
  var called = false
  loop.resolveAddrAsync("multi.example", 443, SOCK_STREAM,
    proc(addrs: seq[Sockaddr_storage]; err: string) =
      got = addrs
      errMsg = err
      called = true
  )
  discard pollUntil(loop, proc(): bool = called, 20_000)
  assert called, "callback should fire"
  assert errMsg.len == 0, "no error expected, got: " & errMsg
  assert got.len == 2, "expected 2 addresses, got " & $got.len
  var e1 = sockaddrFromIp("10.1.0.1", 443)
  var e2 = sockaddrFromIp("10.1.0.2", 443)
  let a = cast[ptr Sockaddr_in](unsafeAddr got[0])
  let b = cast[ptr Sockaddr_in](unsafeAddr got[1])
  let ea = cast[ptr Sockaddr_in](unsafeAddr e1)
  let eb = cast[ptr Sockaddr_in](unsafeAddr e2)
  assert cmpMem(addr a.sin_addr, addr ea.sin_addr, 4) == 0, "first IP mismatch"
  assert cmpMem(addr b.sin_addr, addr eb.sin_addr, 4) == 0, "second IP mismatch"
  stopFakeDns(loop, fake)
  loop.close()

test "test_dns_txt_single_record":
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29989)])
  loop.configureDns(200, 2)
  var fake = startFakeDns(loop, 29989)
  fake.txtAnswers["_dmarc.example.com"] = @["v=DMARC1; p=reject; rua=mailto:d@example.com"]

  var got: seq[TxtRecord] = @[]
  var errMsg = ""
  var called = false
  loop.resolveTxtAsync("_dmarc.example.com") do (records: seq[TxtRecord]; err: string):
    got = records
    errMsg = err
    called = true
  discard pollUntil(loop, proc(): bool = called, 20_000)
  assert called, "TXT callback should fire"
  assert errMsg.len == 0, "no error expected, got: " & errMsg
  assert got.len == 1, "expected 1 TXT record, got " & $got.len
  assert got[0].data == "v=DMARC1; p=reject; rua=mailto:d@example.com",
    "TXT data mismatch: " & got[0].data
  assert got[0].name == "_dmarc.example.com",
    "TXT owner name mismatch: " & got[0].name
  stopFakeDns(loop, fake)
  loop.close()

test "test_dns_txt_multiple_strings_concatenated":
  # RFC 7208 §3.3: TXT records may contain multiple character-strings that
  # should be concatenated (whitespace and all) to form the full SPF record.
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29990)])
  loop.configureDns(200, 2)
  var fake = startFakeDns(loop, 29990)
  fake.txtAnswers["example.com"] = @["v=spf1 include:_spf.google.com ~all"]

  var got: seq[TxtRecord] = @[]
  var called = false
  loop.resolveTxtAsync("example.com") do (records: seq[TxtRecord]; err: string):
    got = records
    called = true
  discard pollUntil(loop, proc(): bool = called, 20_000)
  assert called, "TXT callback should fire"
  assert got.len == 1, "expected 1 TXT record"
  assert got[0].data == "v=spf1 include:_spf.google.com ~all",
    "SPF TXT data mismatch: " & got[0].data
  stopFakeDns(loop, fake)
  loop.close()

test "test_dns_txt_no_records":
  # NOERROR but no TXT records published (NODATA for type 16)
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29991)])
  loop.configureDns(200, 2)
  var fake = startFakeDns(loop, 29991)
  # don't set any txtAnswers for "notxt.example"

  var got: seq[TxtRecord] = @[]
  var errMsg = ""
  var called = false
  loop.resolveTxtAsync("notxt.example") do (records: seq[TxtRecord]; err: string):
    got = records
    errMsg = err
    called = true
  discard pollUntil(loop, proc(): bool = called, 20_000)
  assert called, "TXT callback should fire"
  assert errMsg.len == 0, "no error for NODATA, got: " & errMsg
  assert got.len == 0, "expected 0 TXT records"
  stopFakeDns(loop, fake)
  loop.close()

test "test_dns_txt_nxdomain":
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29992)])
  loop.configureDns(200, 2)
  var fake = startFakeDns(loop, 29992)
  fake.answers["dead.example"] = @["nx"]

  var errMsg = ""
  var called = false
  loop.resolveTxtAsync("dead.example") do (records: seq[TxtRecord]; err: string):
    errMsg = err
    called = true
  discard pollUntil(loop, proc(): bool = called, 20_000)
  assert called, "TXT callback should fire"
  assert errMsg.len > 0, "expected NXDOMAIN error"
  assert errMsg.contains("not found"), "unexpected error: " & errMsg
  stopFakeDns(loop, fake)
  loop.close()

test "test_dns_txt_cache":
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29993)])
  loop.configureDns(200, 2)
  var fake = startFakeDns(loop, 29993)
  fake.txtAnswers["cached.example"] = @["v=spf1 +all"]

  var called = false
  loop.resolveTxtAsync("cached.example") do (records: seq[TxtRecord]; err: string):
    called = true
  discard pollUntil(loop, proc(): bool = called, 20_000)
  assert called, "first TXT resolve should complete"
  let queriesAfterFirst = fake.queries
  assert queriesAfterFirst >= 1, "expected at least one query"

  called = false
  loop.resolveTxtAsync("cached.example") do (records: seq[TxtRecord]; err: string):
    called = true
  discard pollUntil(loop, proc(): bool = called, 20_000)
  assert called, "cached TXT resolve should complete"
  assert fake.queries == queriesAfterFirst,
    "cached TXT resolve must not re-query (was " & $fake.queries & ", before " & $queriesAfterFirst & ")"

  stopFakeDns(loop, fake)
  loop.close()

test "test_dns_txt_empty_string":
  # An empty TXT record (0-length character-string) is valid per RFC 1035
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29994)])
  loop.configureDns(200, 2)
  var fake = startFakeDns(loop, 29994)
  fake.txtAnswers["empty.example"] = @[""]

  var got: seq[TxtRecord] = @[]
  var called = false
  loop.resolveTxtAsync("empty.example") do (records: seq[TxtRecord]; err: string):
    got = records
    called = true
  discard pollUntil(loop, proc(): bool = called, 20_000)
  assert called, "TXT callback should fire"
  assert got.len == 1, "expected 1 TXT record"
  assert got[0].data == "", "expected empty TXT data"
  stopFakeDns(loop, fake)
  loop.close()

test "test_dns_txt_dmarc_record":
  # Real-world DMARC record structure
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29995)])
  loop.configureDns(200, 2)
  var fake = startFakeDns(loop, 29995)
  fake.txtAnswers["_dmarc.paypal.com"] = @[
    "v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s; " &
    "rua=mailto:d@paypal.com,mailto:d@paypal.com; " &
    "ruf=mailto:f@paypal.com"
  ]

  var got: seq[TxtRecord] = @[]
  var errMsg = ""
  var called = false
  loop.resolveTxtAsync("_dmarc.paypal.com") do (records: seq[TxtRecord]; err: string):
    got = records
    errMsg = err
    called = true
  discard pollUntil(loop, proc(): bool = called, 20_000)
  assert called, "DMARC TXT callback should fire"
  assert errMsg.len == 0, "no error expected, got: " & errMsg
  assert got.len == 1, "expected 1 TXT record"
  assert got[0].data.startsWith("v=DMARC1"),
    "DMARC record should start with v=DMARC1, got: " & got[0].data
  assert got[0].data.contains("p=reject"),
    "DMARC policy should be reject"
  stopFakeDns(loop, fake)
  loop.close()

when not defined(macosx):
  # Connecting to 127.0.0.2 is refused quickly on Linux/Windows loopback, which
  # is what triggers the fallback. macOS drops the SYN (it never refuses
  # non-127.0.0.1 loopback addresses), so the test cannot complete there — the
  # fallback path is covered by Linux/Windows CI, and multi-address resolution
  # is still tested above.
  proc boundPort(sock: SocketHandle): int =
    ## Read back the kernel-assigned port after binding to :0, so concurrent
    ## runs / leftover listeners can never collide with the test's sockets.
    var sa: Sockaddr_storage
    var sl: SockLen = sizeof(sa).SockLen
    if getsockname(sock, cast[ptr Sockaddr](addr sa), addr sl) != 0:
      raise newException(NetError, "getsockname failed")
    let p = cast[ptr Sockaddr_in](unsafeAddr sa).sin_port.uint16
    result = ((p shr 8) or ((p and 0xFF'u16) shl 8)).int   # ntohs

  test "test_dns_connect_fallback_across_addresses":
    # multi.example resolves to [127.0.0.2, 127.0.0.1]; the echo server is on
    # 127.0.0.1. connect() must fail on 127.0.0.2 (connection refused) then fall
    # back to 127.0.0.1 and succeed.
    let loop = newLoop()
    var fake = startFakeDns(loop, 0)
    loop.configureDns(300, 2)
    loop.setDnsServers([("127.0.0.1", boundPort(fake.sock.fd))])
    fake.answers["multi.example"] = @["127.0.0.2", "127.0.0.1"]

    var server: TcpServer
    server = newTcpServer(loop,
      onAccept = proc(conn: Connection) = discard,
      onData = proc(conn: Connection, data: openArray[byte]) =
        discard conn.send(data)
    )
    server.listen("127.0.0.1", 0)
    let serverPort = boundPort(server.fd)

    var connected = false
    var received = ""
    var failed = false
    var lastErr = ""
    loop.connect("multi.example", serverPort,
      onConnect = proc(conn: Connection) =
        connected = true
        discard conn.send("fallback ok")
      ,
      onData = proc(conn: Connection, data: openArray[byte]) =
        received = cast[string](@data)
        conn.close()
        server.close()
        loop.stop()
      ,
      onError = proc(err: string) =
        failed = true
        lastErr = err
        echo "  (onError: ", err, ")"
        # A total connect failure must not hang `loop.run()` forever.
        loop.stop()
      ,
    )
    # Safety timeout: fail the test cleanly instead of hanging if the fallback
    # never reaches a reachable address.
    discard loop.addTimer(5000) do (id: int):
      loop.stop()
    loop.run()

    assert connected, "connect should fall back to the reachable address" &
      (if lastErr.len > 0: " (last error: " & lastErr & ")" else: "")
    assert received == "fallback ok",
      "echo mismatch: '" & received & "'"
    assert not failed, "fallback should have succeeded"
    stopFakeDns(loop, fake)
    loop.close()
