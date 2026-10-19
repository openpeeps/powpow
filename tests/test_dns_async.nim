## tests/test_dns_async.nim — Awaitable DNS resolver tests.
##
## Covers the `resolve*Async` Future API from `net/dns.nim`, used with
## `await`/`waitFor` from `std/asyncdispatch`:
## - owned-loop one-shots (IP-literal and /etc/hosts fast paths, no I/O)
## - loop-taking futures against a synthetic DNS responder (fully offline):
##   A query, dual-family merge, TXT, and NXDOMAIN raising `DnsError`.

import ../src/powpow
import std/[unittest, asyncdispatch, strutils, tables]

# ── Minimal synthetic DNS responder (A + TXT + NXDOMAIN) ─────────────────────

type
  FakeDnsAsync = ref object
    sock: UdpSocket
    answers: Table[string, seq[string]]
    txtAnswers: Table[string, seq[string]]

proc decodeAsyncName(msg: seq[byte]; start: int): tuple[name: string, next: int] =
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

proc asyncDnsResponse(id: uint16; qname: string; rcode: int; qtype: uint16;
                      ips: seq[string]): seq[byte] =
  result = newSeq[byte](12)
  result[0] = byte((id shr 8) and 0xFF)
  result[1] = byte(id and 0xFF)
  result[2] = 0x81
  result[3] = byte(0x80 or (rcode and 0x0F))
  result[4] = 0; result[5] = 1
  result[6] = 0; result[7] = byte(if rcode == 0 and ips.len > 0: ips.len else: 0)
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
    result.add(0xC0); result.add(0x0C)
    result.add(byte((qtype shr 8) and 0xFF)); result.add(byte(qtype and 0xFF))
    result.add(0); result.add(1)
    result.add(0); result.add(0); result.add(0); result.add(60)
    result.add(0); result.add(4)
    for part in ip.split('.'):
      result.add(parseInt(part).uint8)

proc startFakeDnsAsync(loop: Loop; port: int): FakeDnsAsync =
  let fake = FakeDnsAsync(
    answers: initTable[string, seq[string]](),
    txtAnswers: initTable[string, seq[string]](),
  )
  fake.sock = loop.bindUdp("127.0.0.1", port,
    onData = proc(sender: Sockaddr_storage; data: openArray[byte]) =
      if data.len < 12:
        return
      let id = (uint16(data[0]) shl 8) or data[1]
      let (name, pos) = decodeAsyncName(@data, 12)
      if pos + 4 > data.len:
        return
      let qtype = (uint16(data[pos]) shl 8) or data[pos + 1]
      let key = name.toLowerAscii()
      if qtype == 16:
        let txts = fake.txtAnswers.getOrDefault(key)
        if txts.len == 0 and key notin fake.txtAnswers:
          discard fake.sock.sendTo(asyncDnsResponse(id, name, 3, qtype, @[]), sender)
          return
        var resp = asyncDnsResponse(id, name, 0, qtype, @[])
        resp[6] = 0; resp[7] = byte(txts.len)
        for txt in txts:
          resp.add(0xC0); resp.add(0x0C)
          resp.add(0); resp.add(16)
          resp.add(0); resp.add(1)
          resp.add(0); resp.add(0); resp.add(0); resp.add(60)
          resp.add(byte(((1 + txt.len) shr 8) and 0xFF))
          resp.add(byte((1 + txt.len) and 0xFF))
          resp.add(byte(txt.len and 0xFF))
          for ch in txt:
            resp.add(ch.uint8)
        discard fake.sock.sendTo(resp, sender)
      elif key in fake.answers and fake.answers[key] == @["nx"]:
        discard fake.sock.sendTo(asyncDnsResponse(id, name, 3, qtype, @[]), sender)
      elif key in fake.answers:
        let ips = fake.answers[key]
        if qtype == 1:
          discard fake.sock.sendTo(asyncDnsResponse(id, name, 0, qtype, ips), sender)
        else:
          # AAAA: empty answer so the resolver falls back / merges v4 only.
          discard fake.sock.sendTo(asyncDnsResponse(id, name, 0, qtype, @[]), sender)
      else:
        discard fake.sock.sendTo(asyncDnsResponse(id, name, 0, qtype, @[]), sender)
  )
  result = fake

proc pumpTo[T](loop: Loop; fut: Future[T]): Future[T] {.async.} =
  ## Drive the powpow `loop` in lockstep with the asyncdispatch dispatcher
  ## until `fut` (created by a loop-taking `resolve*Async`) settles.
  while not fut.finished:
    loop.poll(0)
    if not fut.finished:
      await sleepAsync(1)
  return await fut

# ── Owned-loop one-shots ─────────────────────────────────────────────────────

test "test_dns_async_owned_ip_literal":
  let addrs = waitFor resolveAddrAsync("10.1.2.3", 8080, SOCK_STREAM)
  assert addrs.len == 1, "expected one address, got " & $addrs.len
  assert cast[ptr Sockaddr](unsafeAddr addrs[0]).sa_family == AF_INET.cushort

test "test_dns_async_owned_localhost":
  let addrs = waitFor resolveAddrAsync("localhost", 80, SOCK_STREAM)
  assert addrs.len >= 1, "expected at least one address"

test "test_dns_async_owned_both_literal":
  let addrs = waitFor resolveAddrBothAsync("127.0.0.1", 80)
  assert addrs.len == 1, "expected one address, got " & $addrs.len

# ── Loop-taking futures against the synthetic responder ─────────────────────

test "test_dns_async_loop_ip_literal_immediate":
  let loop = newLoop()
  let fut = resolveAddrAsync(loop, "10.9.8.7", 8080, SOCK_STREAM)
  assert fut.finished, "IP literal should complete synchronously"
  let addrs = waitFor fut
  assert addrs.len == 1
  loop.close()

test "test_dns_async_loop_a_query":
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29991)])
  loop.configureDns(200, 2)
  var fake = startFakeDnsAsync(loop, 29991)
  fake.answers["async.example"] = @["10.0.0.9"]
  proc main() {.async.} =
    let addrs = await pumpTo(loop, resolveAddrAsync(loop, "async.example", 5000, SOCK_STREAM))
    assert addrs.len == 1, "expected one address, got " & $addrs.len
    assert cast[ptr Sockaddr](unsafeAddr addrs[0]).sa_family == AF_INET.cushort
  waitFor main()
  fake.sock.close()
  loop.close()

test "test_dns_async_loop_nxdomain_raises":
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29992)])
  loop.configureDns(200, 2)
  var fake = startFakeDnsAsync(loop, 29992)
  fake.answers["missing.example"] = @["nx"]
  proc main() {.async.} =
    var raised = false
    try:
      discard await pumpTo(loop, resolveAddrAsync(loop, "missing.example", 80, SOCK_STREAM))
    except DnsError:
      raised = true
    assert raised, "NXDOMAIN should raise DnsError"
  waitFor main()
  fake.sock.close()
  loop.close()

test "test_dns_async_loop_both_merges_v4":
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29993)])
  loop.configureDns(200, 2)
  var fake = startFakeDnsAsync(loop, 29993)
  fake.answers["dual.example"] = @["10.0.0.10"]
  proc main() {.async.} =
    let addrs = await pumpTo(loop, resolveAddrBothAsync(loop, "dual.example", 443))
    assert addrs.len == 1, "expected merged v4 address, got " & $addrs.len
    assert cast[ptr Sockaddr](unsafeAddr addrs[0]).sa_family == AF_INET.cushort
  waitFor main()
  fake.sock.close()
  loop.close()

test "test_dns_async_loop_txt":
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29994)])
  loop.configureDns(200, 2)
  var fake = startFakeDnsAsync(loop, 29994)
  fake.txtAnswers["_dmarc.async.example"] = @["v=DMARC1; p=none"]
  proc main() {.async.} =
    let txts = await pumpTo(loop, resolveTxtAsync(loop, "_dmarc.async.example"))
    assert txts.len == 1, "expected one TXT record, got " & $txts.len
    assert txts[0].data == "v=DMARC1; p=none", "unexpected TXT data: " & txts[0].data
  waitFor main()
  fake.sock.close()
  loop.close()

test "test_dns_async_loop_mx_empty_is_valid":
  let loop = newLoop()
  loop.setDnsServers([("127.0.0.1", 29995)])
  loop.configureDns(200, 2)
  var fake = startFakeDnsAsync(loop, 29995)
  proc main() {.async.} =
    # No MX branch in the fake: NOERROR with no answers is a valid empty result.
    let mxs = await pumpTo(loop, resolveMxAsync(loop, "nomx.example"))
    assert mxs.len == 0, "expected empty MX result"
  waitFor main()
  fake.sock.close()
  loop.close()
