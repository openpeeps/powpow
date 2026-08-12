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

import std/[tables, os, strutils]
import ../loop
import ../types
import common

const
  DefaultDnsTimeoutMs = 5_000
  DefaultDnsAttempts  = 2
  DnsPort             = 53
  MaxOutstandingQueries = 256
  NegativeCacheMs     = 30_000
  DnsRecvBufSize      = 2048
  DnsMaxLabelJumps    = 128
  DnsQtypeA           = 1'u16
  DnsQtypeAAAA        = 28'u16

when defined(windows):
  const HostsPath = "C:\\Windows\\System32\\drivers\\etc\\hosts"
else:
  const HostsPath = "/etc/hosts"
  const ResolvConfPath = "/etc/resolv.conf"

type
  DnsCallback* = proc(addrs: seq[Sockaddr_storage]; err: string) {.closure.}

  ResolvedIp* = object
    af: cint
    addr4: array[4, byte]
    addr6: array[16, byte]

  DnsCacheEntry* = object
    addrs: seq[ResolvedIp]
    expiresAt: int64
    negative: bool

  DnsQuery* = ref object
    id: uint16
    hostname: string
    port: int
    sockType: cint
    qtype: uint16
    cb: DnsCallback
    resolver: DnsResolver
    server: Sockaddr_storage   ## nameserver the query is currently directed at
    serverIdx: int
    attemptsLeft: int
    timer: TimerId
    done: bool

  DnsResolver* = ref object of RootObj
    loop: Loop
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

proc parseResponse(msg: openArray[byte]):
    tuple[rcode: int, addrs: seq[ResolvedIp], minTtl: int, truncated: bool] =
  ## Parse a DNS response. Returns the rcode (0 = NOERROR), the A/AAAA
  ## addresses found, the smallest answer TTL, and whether the TC bit was set.
  if msg.len < 12:
    return (1, newSeq[ResolvedIp](), 0, false)
  let flags = (uint16(msg[2]) shl 8) or msg[3]
  if (flags and 0x8000) == 0:
    return (1, newSeq[ResolvedIp](), 0, false)   # not a response
  let truncated = (flags and 0x0200) != 0
  let rcode = int(flags and 0x0F)
  if rcode != 0:
    return (rcode, newSeq[ResolvedIp](), 0, truncated)
  let qd = int(msg[4]) shl 8 or int(msg[5])
  let an = int(msg[6]) shl 8 or int(msg[7])
  var pos = 12
  for i in 0 ..< qd:
    pos = skipName(msg, pos)
    if pos < 0: return (1, newSeq[ResolvedIp](), 0, truncated)
    pos += 4
  var addrs: seq[ResolvedIp]
  var minTtl = 60
  var haveTtl = false
  for i in 0 ..< an:
    pos = skipName(msg, pos)
    if pos < 0: return (1, newSeq[ResolvedIp](), 0, truncated)
    if pos + 10 > msg.len: return (1, newSeq[ResolvedIp](), 0, truncated)
    let qtype = (uint16(msg[pos]) shl 8) or msg[pos + 1]
    let qclass = (uint16(msg[pos + 2]) shl 8) or msg[pos + 3]
    let ttl = (int(msg[pos + 4]) shl 24) or (int(msg[pos + 5]) shl 16) or
              (int(msg[pos + 6]) shl 8) or int(msg[pos + 7])
    let rdlen = (int(msg[pos + 8]) shl 8) or int(msg[pos + 9])
    pos += 10
    if pos + rdlen > msg.len: return (1, newSeq[ResolvedIp](), 0, truncated)
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
    pos += rdlen
  result = (0, addrs, minTtl, truncated)

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
  let sLen = getSockLen(addr server)
  discard sendto(resolver.fd, unsafeAddr msg[0], msg.len.cint, 0,
                 cast[ptr Sockaddr](addr server), sLen)

proc completeQuery(q: DnsQuery; addrs: seq[ResolvedIp]; err: string) =
  if q.done: return
  q.done = true
  q.resolver.queries.del(q.id)
  if q.timer != TimerId(0):
    q.resolver.loop.cancelTimer(q.timer)
    q.timer = TimerId(0)
  if err.len == 0 and addrs.len > 0:
    var outAddrs: seq[Sockaddr_storage]
    for ip in addrs:
      outAddrs.add(makeSockaddr(ip, q.port))
    q.cb(outAddrs, "")
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
  elif q.qtype == DnsQtypeAAAA:
    startAFallback(q)
  else:
    q.completeQuery(newSeq[ResolvedIp](), "DNS: timed out resolving " & q.hostname)

proc onDnsResponse(q: DnsQuery; msg: openArray[byte]) =
  if q.done: return
  let (rcode, addrs, minTtl, truncated) = parseResponse(msg)
  let resolver = q.resolver
  let key = q.hostname.toLowerAscii()
  if truncated:
    q.completeQuery(newSeq[ResolvedIp](),
      "DNS: truncated response for " & q.hostname & " (TCP fallback not implemented)")
    return
  if rcode != 0:
    if rcode == 3:
      resolver.cache[key] =
        DnsCacheEntry(addrs: @[], expiresAt: monoMs() + NegativeCacheMs, negative: true)
    q.completeQuery(newSeq[ResolvedIp](),
      "DNS: " & (if rcode == 3: "host not found: " else: "query failed (rcode " & $rcode & "): ") &
      q.hostname)
  elif addrs.len > 0:
    resolver.cache[key] =
      DnsCacheEntry(addrs: addrs, expiresAt: monoMs() + int64(minTtl) * 1000, negative: false)
    q.completeQuery(addrs, "")
  elif q.qtype == DnsQtypeAAAA:
    # Name exists but has no AAAA records — fall back to A.
    startAFallback(q)
  else:
    q.completeQuery(newSeq[ResolvedIp](), "DNS: no addresses for " & q.hostname)

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
    fd: SocketHandle(-1),
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

  let key = address.toLowerAscii()

  if loop.dns != nil:
    let r = cast[DnsResolver](loop.dns)
    let cached = r.cache.getOrDefault(key)
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
      r.cache.del(key)

  let h = getHosts().getOrDefault(key)
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
    if r.fd.int >= 0:
      r.loop.unregister(r.fd.int)
      sockClose(r.fd)
      r.fd = SocketHandle(-1)
    for q in r.queries.values:
      if q.timer != TimerId(0):
        r.loop.cancelTimer(q.timer)
    r.queries.clear()
    loop.dns = nil
