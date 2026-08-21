# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/net/dns.nim — In-loop DNS resolver (RFC 1035).
##
## Resolves hostnames to socket addresses entirely on the event loop, without
## blocking `getaddrinfo`. It reads the system resolver config (`/etc/hosts`
## and `/etc/resolv.conf` on POSIX), sends A/AAAA queries over a UDP socket
## owned by the loop, retries with the configured timeout/attempts, and caches
## results by their TTL.
##
## `tcp.connect` uses this resolver, so outbound TCP connections no longer
## block the loop on DNS. The resolver runs with no worker threads and no
## `--threads:on` requirement.
##
## The wire codec, query state machine, cache and public API are shared by both
## backends; only the UDP I/O differs:
##   - readiness (default): a raw socket registered for {Read}, `sendto`/
##     `recvfrom` in the event callback.
##   - io_uring (`when iouEnabled`): an op-driven `UdpSocket` (`RECVMSG`/
##     `SENDMSG` — with `IORING_FEAT_FAST_POLL` the kernel arms an internal
##     poll when the socket is not ready, so no readiness watcher is needed).

import std/[tables, os, strutils]
import ../types
import ../loop
import common
when iouEnabled:
  import udp

const
  DefaultDnsTimeoutMs = 5_000
  DefaultDnsAttempts  = 2
  DnsPort             = 53
  MaxOutstandingQueries = 256
  NegativeCacheMs     = 30_000
  DnsRecvBufSize      = 2048
  DnsMaxLabelJumps    = 128
  DnsQtypeA           = 1'u16
  DnsQtypeMX          = 15'u16
  DnsQtypeAAAA        = 28'u16

when defined(windows):
  const HostsPath = "C:\\Windows\\System32\\drivers\\etc\\hosts"
else:
  const HostsPath = "/etc/hosts"
  const ResolvConfPath = "/etc/resolv.conf"

type
  DnsCallback* = proc(addrs: seq[Sockaddr_storage]; err: string) {.closure.}

  MxRecord* = object
    pref*: int
    exchange*: string

  MxCallback* = proc(records: seq[MxRecord]; err: string) {.closure.}

  ResolvedIp* = object
    af: cint
    addr4: array[4, byte]
    addr6: array[16, byte]

  DnsCacheEntry* = object
    addrs: seq[ResolvedIp]
    mxs: seq[MxRecord]
    expiresAt: int64
    negative: bool

  DnsQuery* = ref object
    id: uint16
    hostname: string
    port: int
    sockType: cint
    qtype: uint16
    cb: DnsCallback
    mcb: MxCallback
    resolver: DnsResolver
    server: Sockaddr_storage   ## nameserver the query is currently directed at
    serverIdx: int
    attemptsLeft: int
    timer: TimerId
    done: bool

  DnsResolver* = ref object of RootObj
    loop: Loop
    when iouEnabled:
      sock: UdpSocket
    else:
      fd: SocketHandle
    nextId: uint16
    queries: Table[uint16, DnsQuery]
    cache: Table[string, DnsCacheEntry]
    nameservers: seq[Sockaddr_storage]
    timeoutMs: int
    attempts: int

# ── IP helpers ────────────────────────────────────────────────────────────────

proc parseIpLiteral(ip: string): ResolvedIp =
  result.af = AF_INET.cint
  if inet_pton(AF_INET, ip.cstring, cast[pointer](addr result.addr4[0])) == 1:
    return
  result.af = AF_INET6.cint
  if inet_pton(AF_INET6, ip.cstring, cast[pointer](addr result.addr6[0])) == 1:
    return
  raise newException(NetError, "invalid IP literal: " & ip)

proc makeSockaddr(ip: ResolvedIp; port: int): Sockaddr_storage =
  var res: Sockaddr_storage
  if ip.af == AF_INET.cint:
    var sain: Sockaddr_in
    when defined(windows):
      sain.sin_family = AF_INET.cushort
    else:
      sain.sin_family = TSa_Family(AF_INET)
    sain.sin_port = htons(port.uint16)
    copyMem(addr sain.sin_addr, unsafeAddr ip.addr4[0], 4)
    copyMem(addr res, addr sain, sizeof(sain))
  else:
    var sai6: Sockaddr_in6
    when defined(windows):
      sai6.sin6_family = AF_INET6.cushort
    else:
      sai6.sin6_family = TSa_Family(AF_INET6)
    sai6.sin6_port = htons(port.uint16)
    copyMem(addr sai6.sin6_addr, unsafeAddr ip.addr6[0], 16)
    copyMem(addr res, addr sai6, sizeof(sai6))
  result = res

proc sameEndpoint(a, b: Sockaddr_storage): bool =
  ## True when two socket addresses point at the same (IP, port).
  let sa = cast[ptr Sockaddr](unsafeAddr a)
  let sb = cast[ptr Sockaddr](unsafeAddr b)
  if sa.sa_family != sb.sa_family:
    return false
  if sa.sa_family == AF_INET.cushort:
    let a4 = cast[ptr Sockaddr_in](unsafeAddr a)
    let b4 = cast[ptr Sockaddr_in](unsafeAddr b)
    return a4.sin_port == b4.sin_port and
           cmpMem(addr a4.sin_addr, addr b4.sin_addr, 4) == 0
  else:
    let a6 = cast[ptr Sockaddr_in6](unsafeAddr a)
    let b6 = cast[ptr Sockaddr_in6](unsafeAddr b)
    return a6.sin6_port == b6.sin6_port and
           cmpMem(addr a6.sin6_addr, addr b6.sin6_addr, 16) == 0

# ── Wire codec (RFC 1035) ─────────────────────────────────────────────────────

proc buildQuery(id: uint16; hostname: string; qtype: uint16): seq[byte] =
  result = newSeq[byte](12)
  result[0] = byte((id shr 8) and 0xFF)
  result[1] = byte(id and 0xFF)
  result[2] = 0x01; result[3] = 0x00       # flags: RD
  result[4] = 0x00; result[5] = 0x01       # QDCOUNT = 1
  result[6] = 0x00; result[7] = 0x00       # ANCOUNT
  result[8] = 0x00; result[9] = 0x00       # NSCOUNT
  result[10] = 0x00; result[11] = 0x01     # ARCOUNT = 1 (EDNS0 OPT)
  for label in hostname.split('.'):
    if label.len == 0 or label.len > 63:
      continue
    result.add(label.len.uint8)
    for ch in label:
      result.add(ch.uint8)
  result.add(0)
  result.add(byte((qtype shr 8) and 0xFF)); result.add(byte(qtype and 0xFF))
  result.add(0x00); result.add(0x01)       # QCLASS = IN
  # EDNS0 OPT record (payload size 1232) to reduce truncation of large answers
  result.add(0)                            # root name
  result.add(0x00); result.add(0x29)       # TYPE = OPT (41)
  result.add(0x04); result.add(0xD0)       # CLASS = UDP payload size 1232
  result.add(0x00); result.add(0x00); result.add(0x00); result.add(0x00)  # TTL
  result.add(0x00); result.add(0x00)       # RDLENGTH = 0

proc skipName(msg: openArray[byte]; start: int): int =
  ## Position after the (possibly compressed) name at `start`, or -1 on
  ## malformed data. Compression pointers are bounded to defeat loops.
  var pos = start
  var jumps = 0
  while pos < msg.len:
    let b = msg[pos]
    if b == 0:
      return pos + 1
    if (b and 0xC0) == 0xC0:
      if pos + 1 >= msg.len: return -1
      inc jumps
      if jumps > DnsMaxLabelJumps: return -1
      return pos + 2
    if (b and 0xC0) != 0:
      return -1
    pos += 1 + b.int
    if pos > msg.len: return -1
  return -1

proc readName(msg: openArray[byte]; start: int): tuple[name: string, next: int] =
  ## Decode a (possibly compressed) domain name starting at `start`.
  ## Returns the decoded name (no trailing dot) and the position just past the
  ## name in the original stream, or ("", -1) on malformed data. Pointers are
  ## bounded by DnsMaxLabelJumps to defeat compression loops.
  var parts: seq[string]
  var pos = start
  var next = -1
  var jumps = 0
  while pos < msg.len:
    let b = msg[pos]
    if b == 0:
      if next < 0: next = pos + 1
      return (parts.join("."), next)
    if (b and 0xC0) == 0xC0:
      if pos + 1 >= msg.len: return ("", -1)
      if next < 0: next = pos + 2
      inc jumps
      if jumps > DnsMaxLabelJumps: return ("", -1)
      pos = ((b.int and 0x3F) shl 8) or msg[pos + 1].int
      continue
    if (b and 0xC0) != 0:
      return ("", -1)
    if pos + 1 + b.int > msg.len: return ("", -1)
    var label = newString(b.int)
    for i in 0 ..< b.int:
      label[i] = chr(msg[pos + 1 + i])
    parts.add(label)
    pos += 1 + b.int
  return ("", -1)

proc parseResponse(msg: openArray[byte]):
    tuple[rcode: int, addrs: seq[ResolvedIp], mxs: seq[MxRecord], minTtl: int, truncated: bool] =
  ## Parse a DNS response. Returns the rcode (0 = NOERROR), the A/AAAA
  ## addresses found, any MX records, the smallest answer TTL, and whether the
  ## TC bit was set.
  if msg.len < 12:
    return (1, newSeq[ResolvedIp](), newSeq[MxRecord](), 0, false)
  let flags = (uint16(msg[2]) shl 8) or msg[3]
  if (flags and 0x8000) == 0:
    return (1, newSeq[ResolvedIp](), newSeq[MxRecord](), 0, false)   # not a response
  let truncated = (flags and 0x0200) != 0
  let rcode = int(flags and 0x0F)
  if rcode != 0:
    return (rcode, newSeq[ResolvedIp](), newSeq[MxRecord](), 0, truncated)
  let qd = int(msg[4]) shl 8 or int(msg[5])
  let an = int(msg[6]) shl 8 or int(msg[7])
  var pos = 12
  for i in 0 ..< qd:
    pos = skipName(msg, pos)
    if pos < 0: return (1, newSeq[ResolvedIp](), newSeq[MxRecord](), 0, truncated)
    pos += 4
  var addrs: seq[ResolvedIp]
  var mxs: seq[MxRecord]
  var minTtl = 60
  var haveTtl = false
  for i in 0 ..< an:
    pos = skipName(msg, pos)
    if pos < 0: return (1, newSeq[ResolvedIp](), newSeq[MxRecord](), 0, truncated)
    if pos + 10 > msg.len: return (1, newSeq[ResolvedIp](), newSeq[MxRecord](), 0, truncated)
    let qtype = (uint16(msg[pos]) shl 8) or msg[pos + 1]
    let qclass = (uint16(msg[pos + 2]) shl 8) or msg[pos + 3]
    let ttl = (int(msg[pos + 4]) shl 24) or (int(msg[pos + 5]) shl 16) or
              (int(msg[pos + 6]) shl 8) or int(msg[pos + 7])
    let rdlen = (int(msg[pos + 8]) shl 8) or int(msg[pos + 9])
    pos += 10
    if pos + rdlen > msg.len: return (1, newSeq[ResolvedIp](), newSeq[MxRecord](), 0, truncated)
    if qclass == 1:
      if not haveTtl or ttl < minTtl:
        minTtl = ttl
        haveTtl = true
      if qtype == DnsQtypeA and rdlen == 4:
        var ip: ResolvedIp
        ip.af = AF_INET.cint
        copyMem(addr ip.addr4[0], addr msg[pos], 4)
        addrs.add(ip)
      elif qtype == DnsQtypeAAAA and rdlen == 16:
        var ip: ResolvedIp
        ip.af = AF_INET6.cint
        copyMem(addr ip.addr6[0], addr msg[pos], 16)
        addrs.add(ip)
      elif qtype == DnsQtypeMX and rdlen >= 3:
        let pref = (int(msg[pos]) shl 8) or msg[pos + 1].int
        let (name, _) = readName(msg, pos + 2)
        if name.len > 0:
          mxs.add(MxRecord(pref: pref, exchange: name.toLowerAscii()))
    pos += rdlen
  result = (0, addrs, mxs, minTtl, truncated)

# ── System config ─────────────────────────────────────────────────────────────

var parsedHosts {.threadvar.}: Table[string, seq[ResolvedIp]]
var parsedHostsOnce {.threadvar.}: bool

proc getHosts(): Table[string, seq[ResolvedIp]] =
  ## Lazily parse /etc/hosts once per thread.
  if parsedHostsOnce:
    return parsedHosts
  parsedHostsOnce = true
  if fileExists(HostsPath):
    let content = HostsPath.readFile()
    let lines = content.splitLines()
    for line in lines:
      let line = line.strip()
      if line.len == 0 or line[0] == '#':
        continue
      let parts = line.splitWhitespace()
      if parts.len < 2:
        continue
      var ip: ResolvedIp
      try:
        ip = parseIpLiteral(parts[0])
      except NetError:
        continue
      for name in parts[1 .. ^1]:
        let key = name.toLowerAscii()
        if key notin parsedHosts:
          parsedHosts[key] = @[]
        parsedHosts[key].add(ip)
  # Modern Windows ships the hosts template with "127.0.0.1 localhost"
  # commented out ("localhost name resolution is handled within DNS itself").
  # localhost must always resolve to loopback, so guarantee it.
  if "localhost" notin parsedHosts:
    parsedHosts["localhost"] = @[parseIpLiteral("127.0.0.1")]
  result = parsedHosts

proc parseResolvConf(): tuple[nameservers: seq[ResolvedIp], timeoutMs: int, attempts: int] =
  result = (newSeq[ResolvedIp](), DefaultDnsTimeoutMs, DefaultDnsAttempts)
  when not defined(windows):
    if fileExists(ResolvConfPath):
      for line in ResolvConfPath.readFile().splitLines():
        let line = line.strip()
        if line.len == 0 or line[0] == '#' or line[0] == ';':
          continue
        let parts = line.splitWhitespace()
        if parts.len < 2:
          continue
        case parts[0]
        of "nameserver":
          try:
            result.nameservers.add(parseIpLiteral(parts[1]))
          except NetError:
            discard
        of "options":
          for opt in parts[1 .. ^1]:
            let eq = opt.find('=')
            if eq > 0:
              let key = opt[0 ..< eq]
              let val = opt[eq + 1 .. ^1]
              case key
              of "timeout":
                try:
                  let v = parseInt(val)
                  if v > 0: result.timeoutMs = v * 1000
                except ValueError:
                  discard
              of "attempts":
                try:
                  let v = parseInt(val)
                  if v > 0: result.attempts = v
                except ValueError:
                  discard
              else: discard
        else: discard

proc defaultNameservers(): seq[ResolvedIp] =
  @[parseIpLiteral("8.8.8.8"), parseIpLiteral("1.1.1.1")]

# ── Resolver internals ────────────────────────────────────────────────────────

proc cacheKey(hostname: string; qtype: uint16): string =
  ## Cache entries are keyed by record type so A/AAAA/MX answers for the same
  ## name never collide.
  case qtype
  of DnsQtypeA: "a/" & hostname.toLowerAscii()
  of DnsQtypeAAAA: "aaaa/" & hostname.toLowerAscii()
  of DnsQtypeMX: "mx/" & hostname.toLowerAscii()
  else: "q" & $qtype & "/" & hostname.toLowerAscii()

proc nextQueryId(resolver: DnsResolver): uint16 =
  while true:
    inc resolver.nextId
    if resolver.nextId == 0:
      inc resolver.nextId
    if resolver.nextId notin resolver.queries:
      return resolver.nextId

proc sendQuery(q: DnsQuery) =
  let resolver = q.resolver
  let server = resolver.nameservers[q.serverIdx mod resolver.nameservers.len]
  q.server = server
  let msg = buildQuery(q.id, q.hostname, q.qtype)
  when iouEnabled:
    discard resolver.sock.sendTo(msg, server)
  else:
    let sLen = getSockLen(addr server)
    discard sendto(resolver.fd, unsafeAddr msg[0], msg.len.cint, 0,
                   cast[ptr Sockaddr](addr server), sLen)

proc completeQuery(q: DnsQuery; addrs: seq[ResolvedIp]; mxs: seq[MxRecord]; err: string) =
  if q.done: return
  q.done = true
  q.resolver.queries.del(q.id)
  if q.timer != TimerId(0):
    q.resolver.loop.cancelTimer(q.timer)
    q.timer = TimerId(0)
  if err.len == 0 and q.mcb != nil:
    # MX query: an empty answer is a valid result (the caller decides whether
    # to fall back to address resolution, e.g. RFC 5321 §5.1).
    q.mcb(mxs, "")
  elif err.len == 0 and addrs.len > 0:
    var outAddrs: seq[Sockaddr_storage]
    for ip in addrs:
      outAddrs.add(makeSockaddr(ip, q.port))
    q.cb(outAddrs, "")
  else:
    if q.mcb != nil:
      q.mcb(newSeq[MxRecord](),
           if err.len > 0: err else: "DNS: no records for " & q.hostname)
    else:
      q.cb(newSeq[Sockaddr_storage](),
           if err.len > 0: err else: "DNS: no addresses for " & q.hostname)

proc startQuery(resolver: DnsResolver; hostname: string; port: int; sockType: cint;
                qtype: uint16; cb: DnsCallback)

proc startAFallback(q: DnsQuery) =
  ## The AAAA query yielded nothing usable — retry with an A query.
  q.done = true
  q.resolver.queries.del(q.id)
  if q.timer != TimerId(0):
    q.resolver.loop.cancelTimer(q.timer)
    q.timer = TimerId(0)
  startQuery(q.resolver, q.hostname, q.port, q.sockType, DnsQtypeA, q.cb)

proc onTimeout(q: DnsQuery) =
  if q.done: return
  q.timer = TimerId(0)
  dec q.attemptsLeft
  if q.attemptsLeft > 0:
    q.serverIdx = (q.serverIdx + 1) mod q.resolver.nameservers.len
    q.resolver.queries.del(q.id)
    q.id = q.resolver.nextQueryId()
    q.resolver.queries[q.id] = q
    q.sendQuery()
    q.timer = q.resolver.loop.addTimer(q.resolver.timeoutMs) do (tid: int):
      onTimeout(q)
  elif q.qtype == DnsQtypeAAAA and q.mcb == nil:
    startAFallback(q)
  else:
    q.completeQuery(newSeq[ResolvedIp](), newSeq[MxRecord](),
                    "DNS: timed out resolving " & q.hostname)

proc onDnsResponse(q: DnsQuery; msg: openArray[byte]) =
  if q.done: return
  let (rcode, addrs, mxs, minTtl, truncated) = parseResponse(msg)
  let resolver = q.resolver
  let key = cacheKey(q.hostname, q.qtype)
  if truncated:
    q.completeQuery(newSeq[ResolvedIp](), newSeq[MxRecord](),
      "DNS: truncated response for " & q.hostname & " (TCP fallback not implemented)")
    return
  if rcode != 0:
    if rcode == 3:
      resolver.cache[key] =
        DnsCacheEntry(addrs: @[], expiresAt: monoMs() + NegativeCacheMs, negative: true)
    let msg = "DNS: " & (if rcode == 3: "host not found: " else: "query failed (rcode " & $rcode & "): ") &
      q.hostname
    q.completeQuery(newSeq[ResolvedIp](), newSeq[MxRecord](), msg)
  elif addrs.len > 0 or (q.mcb != nil and mxs.len > 0):
    if q.mcb != nil:
      resolver.cache[key] =
        DnsCacheEntry(mxs: mxs, expiresAt: monoMs() + int64(minTtl) * 1000, negative: false)
      q.completeQuery(newSeq[ResolvedIp](), mxs, "")
    else:
      resolver.cache[key] =
        DnsCacheEntry(addrs: addrs, expiresAt: monoMs() + int64(minTtl) * 1000, negative: false)
      q.completeQuery(addrs, newSeq[MxRecord](), "")
  elif q.qtype == DnsQtypeAAAA and q.mcb == nil:
    # Name exists but has no AAAA records — fall back to A.
    startAFallback(q)
  else:
    # NOERROR with no usable records. For MX this is a valid empty answer;
    # for address queries it means the name exists without A records.
    if q.mcb != nil:
      resolver.cache[key] =
        DnsCacheEntry(mxs: @[], expiresAt: monoMs() + int64(minTtl) * 1000, negative: false)
      q.completeQuery(newSeq[ResolvedIp](), newSeq[MxRecord](), "")
    else:
      q.completeQuery(newSeq[ResolvedIp](), newSeq[MxRecord](), "DNS: no addresses for " & q.hostname)

proc startQuery(resolver: DnsResolver; hostname: string; port: int; sockType: cint;
                qtype: uint16; cb: DnsCallback) =
  if resolver.queries.len >= MaxOutstandingQueries:
    cb(newSeq[Sockaddr_storage](), "DNS: too many outstanding queries")
    return
  let id = resolver.nextQueryId()
  let q = DnsQuery(
    id: id, hostname: hostname, port: port, sockType: sockType,
    qtype: qtype, cb: cb, resolver: resolver,
    serverIdx: 0, attemptsLeft: resolver.attempts, timer: TimerId(0),
    done: false,
  )
  resolver.queries[id] = q
  q.sendQuery()
  q.timer = resolver.loop.addTimer(resolver.timeoutMs) do (tid: int):
    onTimeout(q)

proc startMxQuery(resolver: DnsResolver; domain: string; mcb: MxCallback) =
  if resolver.queries.len >= MaxOutstandingQueries:
    mcb(newSeq[MxRecord](), "DNS: too many outstanding queries")
    return
  let id = resolver.nextQueryId()
  let q = DnsQuery(
    id: id, hostname: domain, port: 0, sockType: 0,
    qtype: DnsQtypeMX, mcb: mcb, resolver: resolver,
    serverIdx: 0, attemptsLeft: resolver.attempts, timer: TimerId(0),
    done: false,
  )
  resolver.queries[id] = q
  q.sendQuery()
  q.timer = resolver.loop.addTimer(resolver.timeoutMs) do (tid: int):
    onTimeout(q)

# ── Receive dispatch ──────────────────────────────────────────────────────────

when iouEnabled:
  proc onDnsDatagram(resolver: DnsResolver; sender: Sockaddr_storage;
                     data: openArray[byte]) =
    if data.len < 12:
      return
    let id = (uint16(data[0]) shl 8) or data[1]
    let q = resolver.queries.getOrDefault(id)
    if q == nil or q.done:
      return
    if not sameEndpoint(sender, q.server):
      return   # not from the nameserver we queried — ignore
    onDnsResponse(q, data)
else:
  proc onDnsReadable(resolver: DnsResolver) =
    var buf: array[DnsRecvBufSize, byte]
    while true:
      var src {.noInit.}: Sockaddr_storage
      var srcLen: SockLen = sizeof(src).SockLen
      let n = recvfrom(resolver.fd, addr buf[0], buf.len.cint, 0,
                       cast[ptr Sockaddr](addr src), addr srcLen)
      if n <= 0:
        break
      if n < 12:
        continue
      let id = (uint16(buf[0]) shl 8) or buf[1]
      let q = resolver.queries.getOrDefault(id)
      if q == nil or q.done:
        continue
      if not sameEndpoint(src, q.server):
        continue   # not from the nameserver we queried — ignore
      onDnsResponse(q, buf.toOpenArray(0, n - 1))

# ── Resolver lifecycle ────────────────────────────────────────────────────────

proc createResolver(loop: Loop): DnsResolver =
  let resolver = DnsResolver(
    loop: loop,
    nextId: 0,
    queries: initTable[uint16, DnsQuery](),
    cache: initTable[string, DnsCacheEntry](),
    nameservers: @[],
    timeoutMs: DefaultDnsTimeoutMs,
    attempts: DefaultDnsAttempts,
  )
  let conf = parseResolvConf()
  resolver.timeoutMs = conf.timeoutMs
  resolver.attempts = conf.attempts
  for ns in conf.nameservers:
    # The resolver socket is AF_INET — IPv6 nameservers (e.g. fe80::1%en0 in
    # resolv.conf) cannot be queried and sendto() fails with EINVAL.
    if ns.af == AF_INET.cint:
      resolver.nameservers.add(makeSockaddr(ns, DnsPort))
  if resolver.nameservers.len == 0:
    for ip in defaultNameservers():
      resolver.nameservers.add(makeSockaddr(ip, DnsPort))

  when iouEnabled:
    resolver.sock = loop.bindUdp("0.0.0.0", 0,
      onData = proc(sender: Sockaddr_storage; data: openArray[byte]) =
        resolver.onDnsDatagram(sender, data))
  else:
    let fd = socket(AF_INET, SOCK_DGRAM, 0)
    if fd.cint < 0:
      raise newException(NetError, "DNS: socket() failed")
    setNonBlocking(fd)
    var local: Sockaddr_in
    when defined(windows):
      local.sin_family = AF_INET.cushort
    else:
      local.sin_family = TSa_Family(AF_INET)
    local.sin_port = 0
    if bindSocket(fd, cast[ptr Sockaddr](addr local), sizeof(local).SockLen) < 0:
      sockClose(fd)
      raise newException(NetError, "DNS: bind() failed")
    resolver.fd = fd
    loop.register(fd.int, {Read},
      edgeTriggered = true,
      callback = proc(rfd: int, ev: set[EventType]) =
        if Error in ev or Hup in ev:
          return
        if Read in ev:
          resolver.onDnsReadable()
    )

  loop.dns = resolver
  loop.addCleanup(proc() =
    when iouEnabled:
      if resolver.sock != nil:
        resolver.sock.close()
        resolver.sock = nil
    else:
      if resolver.fd.int >= 0:
        loop.unregister(resolver.fd.int)
        sockClose(resolver.fd)
        resolver.fd = SocketHandle(-1)
    for q in resolver.queries.values:
      if q.timer != TimerId(0):
        loop.cancelTimer(q.timer)
    resolver.queries.clear()
  )
  result = resolver

proc getResolver(loop: Loop): DnsResolver =
  if loop.dns == nil:
    result = createResolver(loop)
  else:
    result = cast[DnsResolver](loop.dns)

# ── Public API ────────────────────────────────────────────────────────────────

proc resolveAddrAsync*(loop: Loop; address: string; port: int;
                       sockType: cint;
                       cb: proc(addrs: seq[Sockaddr_storage]; err: string) {.closure.}) =
  ## Resolve `address:port` asynchronously on `loop`. `cb` runs on the loop
  ## thread with ALL resolved socket addresses (or an empty seq plus a
  ## non-empty `err` on failure). Never blocks the loop on DNS.
  ##
  ## Numeric IPv4/IPv6 literals resolve immediately without any DNS I/O.
  if isIpAddress(address):
    var addrBuf: Sockaddr_storage
    try:
      addrBuf = sockaddrFromIp(address, port)
    except NetError as e:
      cb(newSeq[Sockaddr_storage](), e.msg)
      return
    cb(@[addrBuf], "")
    return

  let name = address.toLowerAscii()

  if loop.dns != nil:
    let r = cast[DnsResolver](loop.dns)
    # The single-family path prefers AAAA but may have fallen back to A in a
    # previous resolution, so consult both family caches.
    for qtype in [DnsQtypeAAAA, DnsQtypeA]:
      let cached = r.cache.getOrDefault(cacheKey(name, qtype))
      if cached.addrs.len > 0 or cached.negative:
        if cached.expiresAt > monoMs():
          if cached.negative:
            cb(newSeq[Sockaddr_storage](), "DNS: host not found: " & address)
          else:
            var outAddrs: seq[Sockaddr_storage]
            for ip in cached.addrs:
              outAddrs.add(makeSockaddr(ip, port))
            cb(outAddrs, "")
          return
        r.cache.del(cacheKey(name, qtype))

  let h = getHosts().getOrDefault(name)
  if h.len > 0:
    var outAddrs: seq[Sockaddr_storage]
    for ip in h:
      outAddrs.add(makeSockaddr(ip, port))
    cb(outAddrs, "")
    return

  var resolver: DnsResolver
  try:
    resolver = loop.getResolver()
  except CatchableError as e:
    cb(newSeq[Sockaddr_storage](), e.msg)
    return
  startQuery(resolver, address, port, sockType, DnsQtypeAAAA, cb)

proc resolveMxAsync*(loop: Loop; domain: string; mcb: MxCallback) =
  ## Resolve MX records for `domain` asynchronously on `loop`. `mcb` runs on
  ## the loop thread with the records sorted by ascending preference (or an
  ## empty seq when the name exists but publishes no MX — callers decide
  ## whether to fall back to address resolution, e.g. RFC 5321 §5.1). A
  ## non-empty `err` signals NXDOMAIN or a resolver failure. Never blocks the
  ## loop on DNS.
  let key = cacheKey(domain, DnsQtypeMX)
  if loop.dns != nil:
    let r = cast[DnsResolver](loop.dns)
    let cached = r.cache.getOrDefault(key)
    if cached.expiresAt != 0:
      if cached.expiresAt > monoMs():
        if cached.negative:
          mcb(newSeq[MxRecord](), "DNS: host not found: " & domain)
        else:
          mcb(cached.mxs, "")
        return
      r.cache.del(key)

  var resolver: DnsResolver
  try:
    resolver = loop.getResolver()
  except CatchableError as e:
    mcb(newSeq[MxRecord](), e.msg)
    return
  startMxQuery(resolver, domain, mcb)

proc resolveAddrBothAsync*(loop: Loop; address: string; port: int;
                           cb: DnsCallback) =
  ## Resolve both address families for `address` and deliver all socket
  ## addresses ordered IPv6-first (RFC 8305 family-block order) — the input
  ## for Happy Eyeballs connection attempts. If one family fails or is
  ## empty, the other is still delivered; only when both yield nothing does
  ## `cb` fire with an error. Never blocks the loop on DNS.
  if isIpAddress(address):
    var addrBuf: Sockaddr_storage
    try:
      addrBuf = sockaddrFromIp(address, port)
    except NetError as e:
      cb(newSeq[Sockaddr_storage](), e.msg)
      return
    cb(@[addrBuf], "")
    return

  let key = "both/" & address.toLowerAscii()

  if loop.dns != nil:
    let r = cast[DnsResolver](loop.dns)
    let cached = r.cache.getOrDefault(key)
    if cached.expiresAt != 0:
      if cached.expiresAt > monoMs():
        if cached.negative:
          cb(newSeq[Sockaddr_storage](), "DNS: host not found: " & address)
        else:
          var outAddrs: seq[Sockaddr_storage]
          for ip in cached.addrs:
            outAddrs.add(makeSockaddr(ip, port))
          cb(outAddrs, "")
        return
      r.cache.del(key)

  let h = getHosts().getOrDefault(address.toLowerAscii())
  if h.len > 0:
    var outAddrs: seq[Sockaddr_storage]
    for ip in h:
      outAddrs.add(makeSockaddr(ip, port))
    cb(outAddrs, "")
    return

  var resolver: DnsResolver
  try:
    resolver = loop.getResolver()
  except CatchableError as e:
    cb(newSeq[Sockaddr_storage](), e.msg)
    return

  # Fire AAAA and A queries concurrently and merge when both settle.
  type BothState = ref object
    pending: int
    v6: seq[ResolvedIp]
    v4: seq[ResolvedIp]
    errAaaa: string
    errA: string
    finished: bool

  let bs = BothState(pending: 2)

  proc finish() {.closure.} =
    if bs.finished: return
    bs.finished = true
    if bs.v6.len == 0 and bs.v4.len == 0:
      var err = if bs.errA.len > 0: bs.errA else: bs.errAaaa
      if err.len == 0:
        err = "DNS: no addresses for " & address
      cb(newSeq[Sockaddr_storage](), err)
      return
    # Cache the merged list under a short TTL (the per-family entries carry
    # their own authoritative TTLs; the merge itself is refreshed often).
    if loop.dns != nil:
      let r = cast[DnsResolver](loop.dns)
      r.cache[key] = DnsCacheEntry(
        addrs: bs.v6 & bs.v4,
        expiresAt: monoMs() + 60_000,
        negative: false,
      )
    var merged: seq[Sockaddr_storage]
    for ip in bs.v6: merged.add(makeSockaddr(ip, port))
    for ip in bs.v4: merged.add(makeSockaddr(ip, port))
    cb(merged, "")

  proc settle(qtype: uint16; addrs: seq[Sockaddr_storage]; err: string) {.closure.} =
    if qtype == DnsQtypeAAAA:
      dec bs.pending
      if err.len == 0:
        for sa in addrs:
          if sa.ss_family == AF_INET6.cushort:
            var ip: ResolvedIp
            ip.af = AF_INET6.cint
            let s6 = cast[ptr Sockaddr_in6](unsafeAddr sa)
            copyMem(addr ip.addr6[0], addr s6.sin6_addr, 16)
            bs.v6.add(ip)
      else:
        bs.errAaaa = err
    else:
      dec bs.pending
      if err.len == 0:
        for sa in addrs:
          if sa.ss_family == AF_INET.cushort:
            var ip: ResolvedIp
            ip.af = AF_INET.cint
            let s4 = cast[ptr Sockaddr_in](unsafeAddr sa)
            copyMem(addr ip.addr4[0], addr s4.sin_addr, 4)
            bs.v4.add(ip)
      else:
        bs.errA = err
    if bs.pending == 0:
      finish()

  startQuery(resolver, address, port, SOCK_STREAM, DnsQtypeAAAA,
             proc(addrs: seq[Sockaddr_storage]; err: string) {.closure.} =
               settle(DnsQtypeAAAA, addrs, err))
  startQuery(resolver, address, port, SOCK_STREAM, DnsQtypeA,
             proc(addrs: seq[Sockaddr_storage]; err: string) {.closure.} =
               settle(DnsQtypeA, addrs, err))

proc configureDns*(loop: Loop; timeoutMs: int; attempts: int) =
  ## Override the resolver's timeout/attempts (e.g. for tests). Values <= 0
  ## keep the current setting. Creates the resolver if not yet used.
  let resolver = loop.getResolver()
  if timeoutMs > 0:
    resolver.timeoutMs = timeoutMs
  if attempts > 0:
    resolver.attempts = attempts

proc setDnsServers*(loop: Loop; servers: openArray[(string, int)]) =
  ## Point the resolver at specific DNS servers `(address, port)` — e.g. a
  ## local test responder, or ("8.8.8.8", 53). Creates the resolver if not
  ## yet used. Only IPv4 servers are accepted (the resolver socket is AF_INET).
  let resolver = loop.getResolver()
  resolver.nameservers.setLen(0)
  for (address, port) in servers:
    try:
      let ip = parseIpLiteral(address)
      if ip.af == AF_INET.cint:
        resolver.nameservers.add(makeSockaddr(ip, port))
    except NetError:
      discard

proc closeDns*(loop: Loop) =
  ## Force-close the resolver (frees its UDP socket and pending queries).
  ## Normally handled automatically by `loop.close()`.
  let r = cast[DnsResolver](loop.dns)
  if r != nil:
    when iouEnabled:
      if r.sock != nil:
        r.sock.close()
        r.sock = nil
    else:
      if r.fd.int >= 0:
        r.loop.unregister(r.fd.int)
        sockClose(r.fd)
        r.fd = SocketHandle(-1)
    for q in r.queries.values:
      if q.timer != TimerId(0):
        r.loop.cancelTimer(q.timer)
    r.queries.clear()
