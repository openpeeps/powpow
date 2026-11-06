# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/net/dns.nim — In-loop DNS resolver (RFC 1035).
##
## Resolves hostnames to socket addresses entirely on the event loop, without
## blocking `getaddrinfo`. It reads the system resolver config (`/etc/hosts`
## and `/etc/resolv.conf` on POSIX): `search`/`domain` + `ndots` expand short
## names to candidate FQDNs (trailing dot disables expansion), `timeout` /
## `attempts` bound retries, and IPv4 + IPv6 nameservers (with optional
## `%scope`) are each served by their own UDP socket owned by the loop.
## Truncated (TC=1) UDP answers are retried over TCP (RFC 1035 §4.2.2) on a
## transient non-blocking connection to the same nameserver, and results are
## cached by their TTL — no worker threads, no `--threads:on` requirement.
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

import std/[tables, os, strutils, asyncdispatch]
import ../types
import ../loop
import common
when iouEnabled:
  import udp

const
  DefaultDnsTimeoutMs = 5_000
  DefaultDnsAttempts  = 2
  DefaultNdots        = 1
  MaxSearchDomains    = 6   ## glibc MAXDNSRCH: at most 6 search domains
  DnsPort             = 53
  MaxOutstandingQueries = 256
  NegativeCacheMs     = 30_000
  DnsRecvBufSize      = 2048
  DnsMaxLabelJumps    = 128
  DnsQtypeA           = 1'u16
  DnsQtypeMX          = 15'u16
  DnsQtypeTXT         = 16'u16
  DnsQtypeAAAA        = 28'u16

when defined(windows):
  const HostsPath = "C:\\Windows\\System32\\drivers\\etc\\hosts"
else:
  const HostsPath = "/etc/hosts"
  const ResolvConfPath = "/etc/resolv.conf"

type
  DnsError* = object of CatchableError
    ## Raised by the awaitable `resolve*Async` procs when resolution fails
    ## (NXDOMAIN, timeout, no records). The callback API reports the same
    ## failures as an `err: string` instead.

  DnsCallback* = proc(addrs: seq[Sockaddr_storage]; err: string) {.closure.}

  MxRecord* = object
    pref*: int
    exchange*: string

  MxCallback* = proc(records: seq[MxRecord]; err: string) {.closure.}

  TxtRecord* = object
    ## A single TXT record returned by the DNS resolver.
    name*: string
      ## The owner name of the record (e.g. "_dmarc.example.com").
    data*: string
      ## The full TXT string (character-strings concatenated per RFC 1035 §3.3.14).
    ttl*: int
      ## Time-to-live in seconds.

  TxtCallback* = proc(records: seq[TxtRecord]; err: string) {.closure.}

  ResolvedIp* = object
    af: cint
    addr4: array[4, byte]
    addr6: array[16, byte]
    scope*: uint32
      ## IPv6 scope ID (e.g. from `fe80::1%eth0` in resolv.conf). Zero means
      ## no scope; only meaningful when `af` is AF_INET6.

  DnsCacheEntry* = object
    addrs: seq[ResolvedIp]
    mxs: seq[MxRecord]
    txts: seq[TxtRecord]
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
    tcb: TxtCallback
    resolver: DnsResolver
    server: Sockaddr_storage   ## nameserver the query is currently directed at
    serverIdx: int
    attemptsLeft: int
    timer: TimerId
    done: bool
    tcpFd: SocketHandle        ## TCP fallback socket, -1 when no TCP in flight
    tcpActive: bool            ## true while a truncated answer is retried over TCP
    tcpConnected: bool         ## TCP three-way handshake completed
    tcpSendBuf: seq[byte]      ## length-prefixed query (RFC 1035 §4.2.2)
    tcpSendOff: int
    tcpInBuf: seq[byte]        ## received-but-unparsed byte stream
    tcpMsgLen: int             ## -1 until the length prefix arrives, -2 = poisoned
    tcpRecvBuf: seq[byte]      ## the parsed frame (without prefix) once complete

  DnsResolver* = ref object of RootObj
    loop: Loop
    when iouEnabled:
      sock: UdpSocket
    else:
      fd: SocketHandle
    fd6: SocketHandle       ## IPv6 UDP socket, -1 when no IPv6 nameserver
    nextId: uint16
    queries: Table[uint16, DnsQuery]
    cache: Table[string, DnsCacheEntry]
    nameservers: seq[Sockaddr_storage]
    timeoutMs: int
    attempts: int
    searchDomains: seq[string]  ## resolv.conf `search`/`domain` (lowercased)
    ndots: int                  ## minimum dots for absolute-first (default 1)

# ── IP helpers ────────────────────────────────────────────────────────────────

when not defined(windows):
  proc if_nametoindex(ifname: cstring): cuint {.importc, header: "<net/if.h>".}

proc parseIpLiteral(ip: string): ResolvedIp =
  result.af = AF_INET.cint
  if inet_pton(AF_INET, ip.cstring, cast[pointer](addr result.addr4[0])) == 1:
    return
  result.af = AF_INET6.cint
  if inet_pton(AF_INET6, ip.cstring, cast[pointer](addr result.addr6[0])) == 1:
    return
  raise newException(NetError, "invalid IP literal: " & ip)

proc parseNameserverIp*(s: string): ResolvedIp =
  ## Parse a nameserver address, accepting an optional `%scope` suffix on
  ## IPv6 literals (`fe80::1%eth0` or `fe80::1%3` as found in resolv.conf).
  ## Interface names resolve via `if_nametoindex`; plain numbers are used
  ## directly. Raises NetError on invalid input.
  var host = s
  var scope: uint32 = 0
  let pct = s.find('%')
  if pct >= 0:
    host = s[0 ..< pct]
    let iface = s[pct + 1 .. ^1]
    if iface.len == 0:
      raise newException(NetError, "invalid nameserver address: " & s)
    var parsed = false
    try:
      scope = parseUInt(iface).uint32
      parsed = true
    except ValueError:
      discard
    if not parsed:
      when not defined(windows):
        let idx = if_nametoindex(iface.cstring)
        if idx == 0:
          raise newException(NetError, "unknown interface: " & iface)
        scope = idx
      else:
        raise newException(NetError, "scoped IPv6 unsupported: " & s)
  result = parseIpLiteral(host)
  if scope != 0:
    if result.af != AF_INET6.cint:
      raise newException(NetError, "scope on non-IPv6 address: " & s)
    result.scope = scope

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
    when defined(windows):
      sai6.sin6_scope_id = ip.scope.int32
    else:
      # sin6_scope_id is uint32 on some libcs (macOS, Linux x64) and int32
      # on others (Linux ARM64 bindings) — convert to the field's own type.
      sai6.sin6_scope_id = typeof(sai6.sin6_scope_id)(ip.scope)
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
    tuple[rcode: int, addrs: seq[ResolvedIp], mxs: seq[MxRecord],
          txts: seq[TxtRecord], minTtl: int, truncated: bool] =
  ## Parse a DNS response. Returns the rcode (0 = NOERROR), the A/AAAA
  ## addresses found, any MX records, any TXT records, the smallest answer
  ## TTL, and whether the TC bit was set.
  if msg.len < 12:
    return (1, @[], @[], @[], 0, false)
  let flags = (uint16(msg[2]) shl 8) or msg[3]
  if (flags and 0x8000) == 0:
    return (1, @[], @[], @[], 0, false)   # not a response
  let truncated = (flags and 0x0200) != 0
  let rcode = int(flags and 0x0F)
  if rcode != 0:
    return (rcode, @[], @[], @[], 0, truncated)
  let qd = int(msg[4]) shl 8 or int(msg[5])
  let an = int(msg[6]) shl 8 or int(msg[7])
  var pos = 12
  for i in 0 ..< qd:
    pos = skipName(msg, pos)
    if pos < 0: return (1, @[], @[], @[], 0, truncated)
    pos += 4
  var addrs: seq[ResolvedIp]
  var mxs: seq[MxRecord]
  var txts: seq[TxtRecord]
  var minTtl = 60
  var haveTtl = false
  for i in 0 ..< an:
    let nameStart = pos
    pos = skipName(msg, pos)
    if pos < 0: return (1, @[], @[], @[], 0, truncated)
    if pos + 10 > msg.len: return (1, @[], @[], @[], 0, truncated)
    let qtype = (uint16(msg[pos]) shl 8) or msg[pos + 1]
    let qclass = (uint16(msg[pos + 2]) shl 8) or msg[pos + 3]
    let ttl = (int(msg[pos + 4]) shl 24) or (int(msg[pos + 5]) shl 16) or
              (int(msg[pos + 6]) shl 8) or int(msg[pos + 7])
    let rdlen = (int(msg[pos + 8]) shl 8) or int(msg[pos + 9])
    pos += 10
    if pos + rdlen > msg.len: return (1, @[], @[], @[], 0, truncated)
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
      elif qtype == DnsQtypeTXT and rdlen >= 1:
        # RFC 1035 §3.3.14: one or more character-strings, each prefixed
        # with a 1-byte length.  Concatenate them to form the full text.
        let (ownerName, _) = readName(msg, nameStart)
        var txtData = ""
        var rpos = pos
        let rEnd = pos + rdlen
        while rpos < rEnd:
          let slen = int(msg[rpos])
          inc rpos
          if rpos + slen > rEnd: break
          for j in 0 ..< slen:
            txtData.add(chr(msg[rpos + j]))
          rpos += slen
        txts.add(TxtRecord(name: ownerName.toLowerAscii(),
                           data: txtData, ttl: ttl))
    pos += rdlen
  result = (0, addrs, mxs, txts, minTtl, truncated)

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

proc parseResolvConfContent*(content: string):
    tuple[nameservers: seq[ResolvedIp], timeoutMs: int, attempts: int,
          search: seq[string], ndots: int] =
  ## Parse resolv.conf text (pure function of the content, so it is directly
  ## unit-testable). Understands `nameserver` (IPv4 and IPv6 with optional
  ## `%scope`), `search` / `domain` (last one wins, capped at 6), and
  ## `options timeout:` / `attempts:` / `ndots:` (both `:` and `=` forms).
  result = (newSeq[ResolvedIp](), DefaultDnsTimeoutMs, DefaultDnsAttempts,
            newSeq[string](), DefaultNdots)
  for line in content.splitLines():
    let line = line.strip()
    if line.len == 0 or line[0] == '#' or line[0] == ';':
      continue
    let parts = line.splitWhitespace()
    if parts.len < 2:
      continue
    case parts[0]
    of "nameserver":
      try:
        result.nameservers.add(parseNameserverIp(parts[1]))
      except NetError:
        discard
    of "search":
      result.search.setLen(0)
      for d in parts[1 .. ^1]:
        if result.search.len >= MaxSearchDomains:
          break
        let dd = d.strip(chars = {'.'}).toLowerAscii()
        if dd.len > 0:
          result.search.add(dd)
    of "domain":
      # `search` and `domain` are mutually exclusive; the last one in file
      # order wins, so both simply overwrite.
      let dd = parts[1].strip(chars = {'.'}).toLowerAscii()
      result.search = if dd.len > 0: @[dd] else: @[]
    of "options":
      for opt in parts[1 .. ^1]:
        var sep = opt.find(':')
        if sep < 0:
          sep = opt.find('=')
        if sep > 0:
          let key = opt[0 ..< sep]
          let val = opt[sep + 1 .. ^1]
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
          of "ndots":
            try:
              let v = parseInt(val)
              if v >= 0 and v <= 15: result.ndots = v
            except ValueError:
              discard
          else: discard
    else: discard

proc parseResolvConf(): tuple[nameservers: seq[ResolvedIp], timeoutMs: int,
                              attempts: int, search: seq[string], ndots: int] =
  result = (newSeq[ResolvedIp](), DefaultDnsTimeoutMs, DefaultDnsAttempts,
            newSeq[string](), DefaultNdots)
  when not defined(windows):
    if fileExists(ResolvConfPath):
      result = parseResolvConfContent(ResolvConfPath.readFile())

proc defaultNameservers(): seq[ResolvedIp] =
  @[parseIpLiteral("8.8.8.8"), parseIpLiteral("1.1.1.1")]

# ── Resolver internals ────────────────────────────────────────────────────────

proc cacheKey(hostname: string; qtype: uint16): string =
  ## Cache entries are keyed by record type so A/AAAA/MX/TXT answers for the
  ## same name never collide.
  case qtype
  of DnsQtypeA: "a/" & hostname.toLowerAscii()
  of DnsQtypeAAAA: "aaaa/" & hostname.toLowerAscii()
  of DnsQtypeMX: "mx/" & hostname.toLowerAscii()
  of DnsQtypeTXT: "txt/" & hostname.toLowerAscii()
  else: "q" & $qtype & "/" & hostname.toLowerAscii()

proc nextQueryId(resolver: DnsResolver): uint16 =
  while true:
    inc resolver.nextId
    if resolver.nextId == 0:
      inc resolver.nextId
    if resolver.nextId notin resolver.queries:
      return resolver.nextId

proc serverFamily(server: Sockaddr_storage): cushort {.inline.} =
  cast[ptr Sockaddr](unsafeAddr server).sa_family

proc sendQuery(q: DnsQuery) =
  let resolver = q.resolver
  let server = resolver.nameservers[q.serverIdx mod resolver.nameservers.len]
  q.server = server
  let msg = buildQuery(q.id, q.hostname, q.qtype)
  if serverFamily(server) == AF_INET6.cushort:
    # IPv6 nameserver: raw socket shared by both backends (a second
    # op-driven UdpSocket would need buffer registration before bind).
    let sLen = getSockLen(addr server)
    discard sendto(resolver.fd6, unsafeAddr msg[0], msg.len.cint, 0,
                   cast[ptr Sockaddr](addr server), sLen)
  else:
    when iouEnabled:
      discard resolver.sock.sendTo(msg, server)
    else:
      let sLen = getSockLen(addr server)
      discard sendto(resolver.fd, unsafeAddr msg[0], msg.len.cint, 0,
                     cast[ptr Sockaddr](addr server), sLen)

proc closeTcp(q: DnsQuery) =
  ## Tear down a TCP fallback socket (if any): unregister the watcher and
  ## close the fd. Safe to call when no TCP is in flight.
  if q.tcpFd.int >= 0:
    q.resolver.loop.unregister(q.tcpFd.int)
    sockClose(q.tcpFd)
    q.tcpFd = SocketHandle(-1)
  q.tcpActive = false
  q.tcpConnected = false

# Forward declarations: the TCP fallback below retries through the same
# timeout/fallback path as UDP.
proc onTimeout(q: DnsQuery)
proc startAFallback(q: DnsQuery)
proc startQuery(resolver: DnsResolver; hostname: string; port: int; sockType: cint;
                qtype: uint16; cb: DnsCallback)
proc onDnsResponse(q: DnsQuery; msg: openArray[byte]; fromTcp: bool)
proc completeQuery(q: DnsQuery; addrs: seq[ResolvedIp]; mxs: seq[MxRecord];
                   txts: seq[TxtRecord]; err: string)

proc retryNextServer(q: DnsQuery) =
  ## Shared retry step: the current attempt (UDP timeout or failed TCP
  ## fallback) is spent — move to the next nameserver while attempts remain,
  ## else AAAA→A fallback or a timeout error. The caller must have cleared
  ## `q.timer` (fired or cancelled) before calling.
  if q.done: return
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
    q.completeQuery(@[], @[], @[],
                    "DNS: timed out resolving " & q.hostname)

proc failTcp(q: DnsQuery) =
  ## A TCP fallback attempt failed (refused, reset, send/recv error,
  ## oversize frame). Spend the attempt and continue on the next nameserver
  ## via UDP — the same outcome as a UDP timeout.
  if q.done: return
  closeTcp(q)
  if q.timer != TimerId(0):
    q.resolver.loop.cancelTimer(q.timer)
    q.timer = TimerId(0)
  retryNextServer(q)

proc pumpTcpSend(q: DnsQuery): bool =
  ## Flush as much of the length-prefixed query as the socket takes.
  ## Returns true when the whole frame is on the wire.
  while q.tcpSendOff < q.tcpSendBuf.len:
    let n = sockSend(q.tcpFd,
                     unsafeAddr q.tcpSendBuf[q.tcpSendOff],
                     q.tcpSendBuf.len - q.tcpSendOff)
    if n > 0:
      q.tcpSendOff += n
    elif sockWouldBlock():
      return false
    else:
      return false  # hard error — caller fails over via failTcp
  return true

proc pumpTcpRecv(q: DnsQuery): bool =
  ## Drain the length-prefixed response. Returns true once a full frame is
  ## available in `tcpRecvBuf` (prefix stripped), false while more bytes are
  ## needed. A hard error returns false with `tcpMsgLen` set to -2 as a
  ## poison flag.
  ##
  ## Transport reads differ by platform: on Windows the IOCP backend serves
  ## inbound bytes from its per-fd WSARecv buffer (`getReadData`) — a raw
  ## recv() would race the posted WSARecv and starve. Whole completions
  ## (<= 4096 bytes, the platform buffer size) are drained at once so a
  ## partially-consumed completion is never truncated and lost.
  const TcpReadChunk = 4096
  when defined(windows):
    var tmp: array[TcpReadChunk, byte]
    let n = q.resolver.loop.platform.getReadData(q.tcpFd.int,
      cast[ptr UncheckedArray[byte]](addr tmp[0]), TcpReadChunk)
    if n > 0:
      let prev = q.tcpInBuf.len
      q.tcpInBuf.setLen(prev + n)
      copyMem(addr q.tcpInBuf[prev], addr tmp[0], n)
    elif n == 0:
      q.tcpMsgLen = -2  # peer closed / socket broken
      return false
    else:
      return false  # nothing completed yet (-1); wait for the next Read
  else:
    var chunk: array[TcpReadChunk, byte]
    while true:
      let n = sockRecv(q.tcpFd, addr chunk[0], chunk.len)
      if n > 0:
        let prev = q.tcpInBuf.len
        q.tcpInBuf.setLen(prev + n)
        copyMem(addr q.tcpInBuf[prev], addr chunk[0], n)
      elif n == 0:
        q.tcpMsgLen = -2  # peer closed mid-message
        return false
      elif sockWouldBlock():
        break
      else:
        q.tcpMsgLen = -2
        return false
  # Frame parse: 2-byte length prefix, then exactly that many bytes.
  if q.tcpInBuf.len > 2 + 65535:
    q.tcpMsgLen = -2  # peer is streaming garbage; bound the staging buffer
    return false
  if q.tcpInBuf.len < 2:
    return false
  let msgLen = (int(q.tcpInBuf[0]) shl 8) or int(q.tcpInBuf[1])
  if msgLen < 12 or msgLen > 65535:
    q.tcpMsgLen = -2  # poison: oversize/malformed frame
    return false
  if q.tcpInBuf.len < 2 + msgLen:
    return false
  q.tcpRecvBuf = q.tcpInBuf[2 ..< 2 + msgLen]
  q.tcpMsgLen = msgLen
  return true

proc onTcpEvent(q: DnsQuery; fd: int; ev: set[EventType]) =
  if q.done or not q.tcpActive or q.tcpFd.int != fd:
    return  # stale event after teardown / fd reuse
  if not q.tcpConnected:
    # kqueue reports a refused connect as Error with no Read/Hup — SO_ERROR
    # may read 0 on that path, so refuse on the event set too (same rule as
    # the TCP client connect path).
    if Error in ev and Read notin ev and Hup notin ev:
      failTcp(q)
      return
    var err: cint = 0
    var errLen: SockLen = sizeof(err).SockLen
    discard getsockopt(q.tcpFd, SOL_SOCKET, SO_ERROR, addr err, addr errLen)
    if err != 0:
      failTcp(q)
      return
    q.tcpConnected = true
  if not q.tcpConnected:
    return
  if Write in ev or Hup in ev or Error in ev:
    if q.tcpSendOff < q.tcpSendBuf.len:
      let before = q.tcpSendOff
      if not pumpTcpSend(q):
        if q.tcpSendOff == before and not sockWouldBlock():
          failTcp(q)
          return
        # Would-block or partial progress: if the socket errored, the next
        # Read/Hup will surface it; keep waiting unless it was a hard error
        # with no progress. A hard error surfaces as -1 without WouldBlock.
        if q.tcpSendOff == before:
          var err: cint = 0
          var errLen: SockLen = sizeof(err).SockLen
          discard getsockopt(q.tcpFd, SOL_SOCKET, SO_ERROR,
                             addr err, addr errLen)
          if err != 0:
            failTcp(q)
            return
      if q.tcpSendOff >= q.tcpSendBuf.len:
        # Request fully sent — reads from here on.
        q.resolver.loop.modify(fd, {Read})
  if Read in ev or Hup in ev:
    if q.tcpSendOff < q.tcpSendBuf.len:
      return  # still sending; reads wait their turn
    if pumpTcpRecv(q):
      let msg = q.tcpRecvBuf
      closeTcp(q)
      if q.timer != TimerId(0):
        q.resolver.loop.cancelTimer(q.timer)
        q.timer = TimerId(0)
      onDnsResponse(q, msg, true)
    elif q.tcpMsgLen == -2:
      failTcp(q)
    elif Hup in ev:
      # Peer closed before delivering a full frame.
      failTcp(q)
  elif Error in ev:
    failTcp(q)

proc startTcpFallback(q: DnsQuery) =
  ## Retry a truncated UDP answer over TCP (RFC 1035 §4.2.2): open a
  ## non-blocking connection to the same nameserver, send the same query
  ## length-prefixed, and parse the (untruncated) reply. Uses a raw socket +
  ## loop watcher — never `tcp.connect`, which would recurse into DNS.
  if q.done or q.tcpActive: return
  var server = q.server
  let fam = serverFamily(server)
  let fd = socket(fam.cint, SOCK_STREAM, 0)
  if fd.int < 0:
    return  # no fd: keep the truncated error path below
  setNonBlocking(fd)
  let sLen = getSockLen(addr server)
  let ret = connect(fd, cast[ptr Sockaddr](addr server), sLen)
  if ret < 0 and not sockInProgress():
    sockClose(fd)
    return
  let msg = buildQuery(q.id, q.hostname, q.qtype)
  q.tcpSendBuf = newSeq[byte](msg.len + 2)
  q.tcpSendBuf[0] = byte((msg.len shr 8) and 0xFF)
  q.tcpSendBuf[1] = byte(msg.len and 0xFF)
  for i, b in msg: q.tcpSendBuf[2 + i] = b
  q.tcpSendOff = 0
  q.tcpInBuf = @[]
  q.tcpMsgLen = -1
  q.tcpRecvBuf = @[]
  q.tcpFd = fd
  q.tcpActive = true
  q.tcpConnected = (ret == 0)
  # The UDP retry timer becomes the TCP deadline.
  if q.timer != TimerId(0):
    q.resolver.loop.cancelTimer(q.timer)
    q.timer = TimerId(0)
  q.timer = q.resolver.loop.addTimer(q.resolver.timeoutMs) do (tid: int):
    onTimeout(q)
  let loop = q.resolver.loop
  if q.tcpConnected:
    # Loopback-fast connect: try an eager send before arming the watcher.
    if pumpTcpSend(q):
      loop.register(fd.int, {Read},
        callback = proc(rfd: int, ev: set[EventType]) = onTcpEvent(q, rfd, ev))
    else:
      loop.register(fd.int, {Read, Write},
        callback = proc(rfd: int, ev: set[EventType]) = onTcpEvent(q, rfd, ev))
  else:
    loop.register(fd.int, {Read, Write},
      callback = proc(rfd: int, ev: set[EventType]) = onTcpEvent(q, rfd, ev))

proc completeQuery(q: DnsQuery; addrs: seq[ResolvedIp]; mxs: seq[MxRecord];
                   txts: seq[TxtRecord]; err: string) =
  if q.done: return
  q.done = true
  closeTcp(q)
  q.resolver.queries.del(q.id)
  if q.timer != TimerId(0):
    q.resolver.loop.cancelTimer(q.timer)
    q.timer = TimerId(0)
  if err.len == 0 and q.tcb != nil:
    q.tcb(txts, "")
  elif err.len == 0 and q.mcb != nil:
    # MX query: an empty answer is a valid result (the caller decides whether
    # to fall back to address resolution, e.g. RFC 5321 §5.1).
    q.mcb(mxs, "")
  elif err.len == 0 and addrs.len > 0:
    var outAddrs: seq[Sockaddr_storage]
    for ip in addrs:
      outAddrs.add(makeSockaddr(ip, q.port))
    q.cb(outAddrs, "")
  else:
    if q.tcb != nil:
      q.tcb(newSeq[TxtRecord](),
           if err.len > 0: err else: "DNS: no records for " & q.hostname)
    elif q.mcb != nil:
      q.mcb(newSeq[MxRecord](),
           if err.len > 0: err else: "DNS: no records for " & q.hostname)
    else:
      q.cb(newSeq[Sockaddr_storage](),
           if err.len > 0: err else: "DNS: no addresses for " & q.hostname)

proc startAFallback(q: DnsQuery) =
  ## The AAAA query yielded nothing usable — retry with an A query.
  q.done = true
  closeTcp(q)
  q.resolver.queries.del(q.id)
  if q.timer != TimerId(0):
    q.resolver.loop.cancelTimer(q.timer)
    q.timer = TimerId(0)
  startQuery(q.resolver, q.hostname, q.port, q.sockType, DnsQtypeA, q.cb)

proc onTimeout(q: DnsQuery) =
  if q.done: return
  closeTcp(q)
  q.timer = TimerId(0)
  retryNextServer(q)

proc onDnsResponse(q: DnsQuery; msg: openArray[byte]; fromTcp: bool) =
  if q.done: return
  let (rcode, addrs, mxs, txts, minTtl, truncated) = parseResponse(msg)
  let resolver = q.resolver
  let key = cacheKey(q.hostname, q.qtype)
  if truncated:
    if fromTcp:
      # A truncated answer over TCP (should not happen) — fail rather than
      # recurse into another TCP connection.
      q.completeQuery(@[], @[], @[],
        "DNS: truncated response over TCP for " & q.hostname)
    else:
      startTcpFallback(q)
      if not q.tcpActive:
        # No fd available: surface the truncation as an error.
        q.completeQuery(@[], @[], @[],
          "DNS: truncated response for " & q.hostname)
    return
  if rcode != 0:
    if rcode == 3:
      resolver.cache[key] =
        DnsCacheEntry(addrs: @[], expiresAt: monoMs() + NegativeCacheMs, negative: true)
    let msg = "DNS: " & (if rcode == 3: "host not found: " else: "query failed (rcode " & $rcode & "): ") &
      q.hostname
    q.completeQuery(@[], @[], @[], msg)
  elif addrs.len > 0 or (q.mcb != nil and mxs.len > 0) or (q.tcb != nil and txts.len > 0):
    if q.tcb != nil:
      resolver.cache[key] =
        DnsCacheEntry(txts: txts, expiresAt: monoMs() + int64(minTtl) * 1000, negative: false)
      q.completeQuery(@[], @[], txts, "")
    elif q.mcb != nil:
      resolver.cache[key] =
        DnsCacheEntry(mxs: mxs, expiresAt: monoMs() + int64(minTtl) * 1000, negative: false)
      q.completeQuery(@[], mxs, @[], "")
    else:
      resolver.cache[key] =
        DnsCacheEntry(addrs: addrs, expiresAt: monoMs() + int64(minTtl) * 1000, negative: false)
      q.completeQuery(addrs, @[], @[], "")
  elif q.qtype == DnsQtypeAAAA and q.mcb == nil and q.tcb == nil:
    # Name exists but has no AAAA records — fall back to A.
    startAFallback(q)
  else:
    # NOERROR with no usable records. For MX/TXT this is a valid empty answer;
    # for address queries it means the name exists without A records.
    if q.tcb != nil:
      resolver.cache[key] =
        DnsCacheEntry(txts: @[], expiresAt: monoMs() + int64(minTtl) * 1000, negative: false)
      q.completeQuery(@[], @[], @[], "")
    elif q.mcb != nil:
      resolver.cache[key] =
        DnsCacheEntry(mxs: @[], expiresAt: monoMs() + int64(minTtl) * 1000, negative: false)
      q.completeQuery(@[], @[], @[], "")
    else:
      q.completeQuery(@[], @[], @[], "DNS: no addresses for " & q.hostname)

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
    done: false, tcpFd: SocketHandle(-1), tcpMsgLen: -1,
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
    done: false, tcpFd: SocketHandle(-1), tcpMsgLen: -1,
  )
  resolver.queries[id] = q
  q.sendQuery()
  q.timer = resolver.loop.addTimer(resolver.timeoutMs) do (tid: int):
    onTimeout(q)

proc startTxtQuery(resolver: DnsResolver; hostname: string; tcb: TxtCallback) =
  if resolver.queries.len >= MaxOutstandingQueries:
    tcb(newSeq[TxtRecord](), "DNS: too many outstanding queries")
    return
  let id = resolver.nextQueryId()
  let q = DnsQuery(
    id: id, hostname: hostname, port: 0, sockType: 0,
    qtype: DnsQtypeTXT, tcb: tcb, resolver: resolver,
    serverIdx: 0, attemptsLeft: resolver.attempts, timer: TimerId(0),
    done: false, tcpFd: SocketHandle(-1), tcpMsgLen: -1,
  )
  resolver.queries[id] = q
  q.sendQuery()
  q.timer = resolver.loop.addTimer(resolver.timeoutMs) do (tid: int):
    onTimeout(q)

# ── Receive dispatch ──────────────────────────────────────────────────────────

proc onDnsPacket(resolver: DnsResolver; sender: Sockaddr_storage;
                 data: openArray[byte]) =
  ## Shared receive path (both backends, UDP and TCP-fallback adjacent):
  ## match a datagram to its query, ignoring spoofed/short packets.
  if data.len < 12:
    return
  let id = (uint16(data[0]) shl 8) or data[1]
  let q = resolver.queries.getOrDefault(id)
  if q == nil or q.done:
    return
  if not sameEndpoint(sender, q.server):
    return   # not from the nameserver we queried — ignore
  onDnsResponse(q, data, false)

when iouEnabled:
  proc onDnsDatagram(resolver: DnsResolver; sender: Sockaddr_storage;
                     data: openArray[byte]) =
    resolver.onDnsPacket(sender, data)

proc onDnsReadable(resolver: DnsResolver; fd: SocketHandle) =
  ## Drain a raw readiness-watched UDP socket: the IPv4 socket on the
  ## readiness backend, and the IPv6 socket on both backends (a POLL_ADD
  ## watcher also works under io_uring).
  var buf: array[DnsRecvBufSize, byte]
  while true:
    var src {.noInit.}: Sockaddr_storage
    var srcLen: SockLen = sizeof(src).SockLen
    let n = recvfrom(fd, addr buf[0], buf.len.cint, 0,
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
    onDnsResponse(q, buf.toOpenArray(0, n - 1), false)

# ── Resolver lifecycle ────────────────────────────────────────────────────────

proc ensureV6Socket(resolver: DnsResolver): bool =
  ## Create the IPv6 UDP socket when an IPv6 nameserver is configured and no
  ## v6 socket exists yet (shared by both backends: a raw readiness watcher
  ## also works under io_uring). On failure (no IPv6 stack) returns false and
  ## the caller drops IPv6 nameservers so queries stay on IPv4.
  var needV6 = false
  for ns in resolver.nameservers:
    if serverFamily(ns) == AF_INET6.cushort:
      needV6 = true
      break
  if not needV6:
    return true
  if resolver.fd6.int >= 0:
    return true
  let fd6 = socket(AF_INET6.cint, SOCK_DGRAM, 0)
  if fd6.cint < 0:
    return false
  setNonBlocking(fd6)
  setIpv6Only(fd6)
  var local6: Sockaddr_in6
  when defined(windows):
    local6.sin6_family = AF_INET6.cushort
  else:
    local6.sin6_family = TSa_Family(AF_INET6)
  local6.sin6_port = 0
  if bindSocket(fd6, cast[ptr Sockaddr](addr local6),
                sizeof(local6).SockLen) < 0:
    sockClose(fd6)
    return false
  resolver.fd6 = fd6
  let loop = resolver.loop
  loop.register(fd6.int, {Read},
    edgeTriggered = true,
    callback = proc(rfd: int, ev: set[EventType]) =
      if Error in ev or Hup in ev:
        return
      if Read in ev:
        resolver.onDnsReadable(fd6)
  )
  return true

proc createResolver(loop: Loop): DnsResolver =
  let resolver = DnsResolver(
    loop: loop,
    nextId: 0,
    queries: initTable[uint16, DnsQuery](),
    cache: initTable[string, DnsCacheEntry](),
    nameservers: @[],
    timeoutMs: DefaultDnsTimeoutMs,
    attempts: DefaultDnsAttempts,
    searchDomains: @[],
    ndots: DefaultNdots,
    fd6: SocketHandle(-1),
  )
  let conf = parseResolvConf()
  resolver.timeoutMs = conf.timeoutMs
  resolver.attempts = conf.attempts
  resolver.searchDomains = conf.search
  resolver.ndots = conf.ndots
  for ns in conf.nameservers:
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
          resolver.onDnsReadable(fd)
    )

  if not resolver.ensureV6Socket():
    # No IPv6 stack: drop IPv6 nameservers so queries stay on IPv4.
    var v4: seq[Sockaddr_storage]
    for ns in resolver.nameservers:
      if serverFamily(ns) != AF_INET6.cushort:
        v4.add(ns)
    resolver.nameservers = v4
  if resolver.nameservers.len == 0:
    for ip in defaultNameservers():
      resolver.nameservers.add(makeSockaddr(ip, DnsPort))

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
    if resolver.fd6.int >= 0:
      loop.unregister(resolver.fd6.int)
      sockClose(resolver.fd6)
      resolver.fd6 = SocketHandle(-1)
    for q in resolver.queries.values:
      closeTcp(q)
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

proc searchCandidates(resolver: DnsResolver; hostname: string): seq[string] =
  ## Search-list expansion (man resolv.conf): a trailing dot disables the
  ## search list entirely; names with at least `ndots` dots are tried absolute
  ## first, shorter names try each search domain first. Always returns at
  ## least one (lowercased) candidate.
  let lower = hostname.toLowerAscii()
  if lower.endsWith('.'):
    if lower.len > 1:
      return @[lower[0 .. ^2]]
    return @[lower]
  if resolver.searchDomains.len == 0:
    return @[lower]
  var dots = 0
  for ch in lower:
    if ch == '.': inc dots
  if dots >= resolver.ndots:
    result = @[lower]
    for d in resolver.searchDomains:
      result.add(lower & "." & d)
  else:
    for d in resolver.searchDomains:
      result.add(lower & "." & d)
    result.add(lower)

# ── Public API ────────────────────────────────────────────────────────────────

proc resolveAddrCandidate(loop: Loop; name: string; port: int;
                              sockType: cint;
                              cb: proc(addrs: seq[Sockaddr_storage];
                                       err: string) {.closure.}) =
  ## Single-candidate address resolution (no search expansion): cache, then
  ## /etc/hosts, then an AAAA query with A fallback on the loop.
  if loop.dns != nil:
    let r = cast[DnsResolver](loop.dns)
    # The single-family path prefers AAAA but may have fallen back to A in a
    # previous resolution, so consult both family caches.
    for qtype in [DnsQtypeAAAA, DnsQtypeA]:
      let cached = r.cache.getOrDefault(cacheKey(name, qtype))
      if cached.addrs.len > 0 or cached.negative:
        if cached.expiresAt > monoMs():
          if cached.negative:
            cb(newSeq[Sockaddr_storage](), "DNS: host not found: " & name)
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
  startQuery(resolver, name, port, sockType, DnsQtypeAAAA, cb)

proc resolveAddr*(loop: Loop; address: string; port: int;
                  sockType: cint;
                  cb: proc(addrs: seq[Sockaddr_storage];
                           err: string) {.closure.}) =
  ## Resolve `address:port` asynchronously on `loop`. `cb` runs on the loop
  ## thread with ALL resolved socket addresses (or an empty seq plus a
  ## non-empty `err` on failure). Never blocks the loop on DNS.
  ##
  ## Numeric IPv4/IPv6 literals resolve immediately without any DNS I/O.
  ## Other names expand through the search list (`setSearchDomains`,
  ## `ndots` rule): candidates are tried in order until one succeeds, and
  ## the last error is reported when all fail. `/etc/hosts` is consulted
  ## for the literal input name first (nsswitch `files` before `dns`), so
  ## hosts entries never trigger search-expansion I/O.
  if isIpAddress(address):
    var addrBuf: Sockaddr_storage
    try:
      addrBuf = sockaddrFromIp(address, port)
    except NetError as e:
      cb(newSeq[Sockaddr_storage](), e.msg)
      return
    cb(@[addrBuf], "")
    return

  let h0 = getHosts().getOrDefault(address.toLowerAscii())
  if h0.len > 0:
    var outAddrs: seq[Sockaddr_storage]
    for ip in h0:
      outAddrs.add(makeSockaddr(ip, port))
    cb(outAddrs, "")
    return

  var resolver: DnsResolver
  try:
    resolver = loop.getResolver()
  except CatchableError as e:
    cb(newSeq[Sockaddr_storage](), e.msg)
    return
  let cands = resolver.searchCandidates(address)
  if cands.len == 1:
    resolveAddrCandidate(loop, cands[0], port, sockType, cb)
    return
  var i = 0
  var lastErr = ""
  proc tryNext() {.closure.} =
    if i >= cands.len:
      cb(newSeq[Sockaddr_storage](),
         if lastErr.len > 0: lastErr else: "DNS: no addresses for " & address)
      return
    let nm = cands[i]
    inc i
    resolveAddrCandidate(loop, nm, port, sockType,
      proc(addrs: seq[Sockaddr_storage]; err: string) {.closure.} =
        if err.len == 0:
          cb(addrs, "")
        elif "too many outstanding" in err:
          cb(newSeq[Sockaddr_storage](), err)
        else:
          lastErr = err
          tryNext())
  tryNext()

proc resolveMxCandidate(loop: Loop; name: string; mcb: MxCallback) =
  ## Single-candidate MX resolution (no search expansion).
  let key = cacheKey(name, DnsQtypeMX)
  if loop.dns != nil:
    let r = cast[DnsResolver](loop.dns)
    let cached = r.cache.getOrDefault(key)
    if cached.expiresAt != 0:
      if cached.expiresAt > monoMs():
        if cached.negative:
          mcb(newSeq[MxRecord](), "DNS: host not found: " & name)
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
  startMxQuery(resolver, name, mcb)

proc resolveMx*(loop: Loop; domain: string; mcb: MxCallback) =
  ## Resolve MX records for `domain` asynchronously on `loop`. `mcb` runs on
  ## the loop thread with the records sorted by ascending preference (or an
  ## empty seq when the name exists but publishes no MX — callers decide
  ## whether to fall back to address resolution, e.g. RFC 5321 §5.1). A
  ## non-empty `err` signals NXDOMAIN or a resolver failure. Never blocks the
  ## loop on DNS. Search-list candidates are tried in order; the last error
  ## is reported when all fail.
  var resolver: DnsResolver
  try:
    resolver = loop.getResolver()
  except CatchableError as e:
    mcb(newSeq[MxRecord](), e.msg)
    return
  let cands = resolver.searchCandidates(domain)
  if cands.len == 1:
    resolveMxCandidate(loop, cands[0], mcb)
    return
  var i = 0
  var lastErr = ""
  proc tryNext() {.closure.} =
    if i >= cands.len:
      mcb(newSeq[MxRecord](),
          if lastErr.len > 0: lastErr else: "DNS: no records for " & domain)
      return
    let nm = cands[i]
    inc i
    resolveMxCandidate(loop, nm,
      proc(records: seq[MxRecord]; err: string) {.closure.} =
        if err.len == 0:
          mcb(records, "")
        elif "too many outstanding" in err:
          mcb(newSeq[MxRecord](), err)
        else:
          lastErr = err
          tryNext())
  tryNext()

proc resolveTxtCandidate(loop: Loop; name: string; tcb: TxtCallback) =
  ## Single-candidate TXT resolution (no search expansion).
  let key = cacheKey(name, DnsQtypeTXT)
  if loop.dns != nil:
    let r = cast[DnsResolver](loop.dns)
    let cached = r.cache.getOrDefault(key)
    if cached.expiresAt != 0:
      if cached.expiresAt > monoMs():
        if cached.negative:
          tcb(newSeq[TxtRecord](), "DNS: host not found: " & name)
        else:
          tcb(cached.txts, "")
        return
      r.cache.del(key)

  var resolver: DnsResolver
  try:
    resolver = loop.getResolver()
  except CatchableError as e:
    tcb(newSeq[TxtRecord](), e.msg)
    return
  startTxtQuery(resolver, name, tcb)

proc resolveTxt*(loop: Loop; hostname: string; tcb: TxtCallback) =
  ## Resolve TXT records for `hostname` asynchronously on `loop`. `tcb` runs
  ## on the loop thread with ALL TXT records found (or an empty seq plus an
  ## empty `err` when the name exists but publishes no TXT records — the
  ## caller decides what that means). A non-empty `err` signals NXDOMAIN or
  ## a resolver failure. Never blocks the loop on DNS. Search-list candidates
  ## are tried in order; the last error is reported when all fail.
  var resolver: DnsResolver
  try:
    resolver = loop.getResolver()
  except CatchableError as e:
    tcb(newSeq[TxtRecord](), e.msg)
    return
  let cands = resolver.searchCandidates(hostname)
  if cands.len == 1:
    resolveTxtCandidate(loop, cands[0], tcb)
    return
  var i = 0
  var lastErr = ""
  proc tryNext() {.closure.} =
    if i >= cands.len:
      tcb(newSeq[TxtRecord](),
          if lastErr.len > 0: lastErr else: "DNS: no records for " & hostname)
      return
    let nm = cands[i]
    inc i
    resolveTxtCandidate(loop, nm,
      proc(records: seq[TxtRecord]; err: string) {.closure.} =
        if err.len == 0:
          tcb(records, "")
        elif "too many outstanding" in err:
          tcb(newSeq[TxtRecord](), err)
        else:
          lastErr = err
          tryNext())
  tryNext()

proc resolveBothCandidate(loop: Loop; name: string; port: int;
                              cb: DnsCallback) =
  ## Single-candidate dual-family resolution (no search expansion).
  ## Family-block order (IPv6 first) is preserved per candidate.
  let key = "both/" & name

  if loop.dns != nil:
    let r = cast[DnsResolver](loop.dns)
    let cached = r.cache.getOrDefault(key)
    if cached.expiresAt != 0:
      if cached.expiresAt > monoMs():
        if cached.negative:
          cb(newSeq[Sockaddr_storage](), "DNS: host not found: " & name)
        else:
          var outAddrs: seq[Sockaddr_storage]
          for ip in cached.addrs:
            outAddrs.add(makeSockaddr(ip, port))
          cb(outAddrs, "")
        return
      r.cache.del(key)

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
        err = "DNS: no addresses for " & name
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

  startQuery(resolver, name, port, SOCK_STREAM, DnsQtypeAAAA,
             proc(addrs: seq[Sockaddr_storage]; err: string) {.closure.} =
               settle(DnsQtypeAAAA, addrs, err))
  startQuery(resolver, name, port, SOCK_STREAM, DnsQtypeA,
             proc(addrs: seq[Sockaddr_storage]; err: string) {.closure.} =
               settle(DnsQtypeA, addrs, err))

proc resolveAddrBoth*(loop: Loop; address: string; port: int;
                      cb: DnsCallback) =
  ## Resolve both address families for `address` and deliver all socket
  ## addresses ordered IPv6-first (RFC 8305 family-block order) — the input
  ## for Happy Eyeballs connection attempts. If one family fails or is
  ## empty, the other is still delivered; only when both yield nothing does
  ## `cb` fire with an error. Never blocks the loop on DNS. Search-list
  ## candidates are tried in order; the last error is reported when all fail.
  ## `/etc/hosts` is consulted for the literal input name first (nsswitch
  ## `files` before `dns`), so hosts entries never trigger search-expansion I/O.
  if isIpAddress(address):
    var addrBuf: Sockaddr_storage
    try:
      addrBuf = sockaddrFromIp(address, port)
    except NetError as e:
      cb(newSeq[Sockaddr_storage](), e.msg)
      return
    cb(@[addrBuf], "")
    return

  let h0 = getHosts().getOrDefault(address.toLowerAscii())
  if h0.len > 0:
    var outAddrs: seq[Sockaddr_storage]
    for ip in h0:
      outAddrs.add(makeSockaddr(ip, port))
    cb(outAddrs, "")
    return

  var resolver: DnsResolver
  try:
    resolver = loop.getResolver()
  except CatchableError as e:
    cb(newSeq[Sockaddr_storage](), e.msg)
    return
  let cands = resolver.searchCandidates(address)
  if cands.len == 1:
    resolveBothCandidate(loop, cands[0], port, cb)
    return
  var i = 0
  var lastErr = ""
  proc tryNext() {.closure.} =
    if i >= cands.len:
      cb(newSeq[Sockaddr_storage](),
         if lastErr.len > 0: lastErr else: "DNS: no addresses for " & address)
      return
    let nm = cands[i]
    inc i
    resolveBothCandidate(loop, nm, port,
      proc(addrs: seq[Sockaddr_storage]; err: string) {.closure.} =
        if err.len == 0:
          cb(addrs, "")
        elif "too many outstanding" in err:
          cb(newSeq[Sockaddr_storage](), err)
        else:
          lastErr = err
          tryNext())
  tryNext()

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
  ## yet used. IPv4 and IPv6 (with optional `%scope`) are accepted; IPv6
  ## entries are dropped when the host has no IPv6 stack. Raises NetError
  ## when nothing usable remains.
  let resolver = loop.getResolver()
  resolver.nameservers.setLen(0)
  for (address, port) in servers:
    try:
      resolver.nameservers.add(makeSockaddr(parseNameserverIp(address), port))
    except NetError:
      discard
  if not resolver.ensureV6Socket():
    var v4: seq[Sockaddr_storage]
    for ns in resolver.nameservers:
      if serverFamily(ns) != AF_INET6.cushort:
        v4.add(ns)
    resolver.nameservers = v4
  if resolver.nameservers.len == 0:
    raise newException(NetError, "setDnsServers: no usable nameservers")

proc setSearchDomains*(loop: Loop; domains: openArray[string]) =
  ## Override the resolver's search list (e.g. from DHCP or for tests).
  ## Entries are lowercased with trailing dots stripped, capped at 6.
  ## Creates the resolver if not yet used.
  let resolver = loop.getResolver()
  resolver.searchDomains.setLen(0)
  for d in domains:
    var dd = d.strip(chars = {'.'}).toLowerAscii()
    if dd.len > 0 and resolver.searchDomains.len < MaxSearchDomains:
      resolver.searchDomains.add(dd)

proc setNdots*(loop: Loop; n: int) =
  ## Override the `ndots` threshold: names with at least `n` dots are tried
  ## absolute first, others try the search list first (default 1, max 15).
  ## Creates the resolver if not yet used.
  let resolver = loop.getResolver()
  if n >= 0 and n <= 15:
    resolver.ndots = n

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
    if r.fd6.int >= 0:
      r.loop.unregister(r.fd6.int)
      sockClose(r.fd6)
      r.fd6 = SocketHandle(-1)
    for q in r.queries.values:
      closeTcp(q)
      if q.timer != TimerId(0):
        r.loop.cancelTimer(q.timer)
    r.queries.clear()

# ── Awaitable API (std/asyncdispatch Futures) ─────────────────────────────────
#
# `resolve*Async` procs return a `Future` for use with `await`/`waitFor`.
# Loop-taking forms wrap the callback API on the caller's loop (the caller
# drives it); loop-less forms own a private loop, pumped cooperatively with
# the asyncdispatch dispatcher until the query settles, then closed.
# Failures raise `DnsError`; the callback API reports them as `err` instead.

proc resolveAddrAsync*(loop: Loop; address: string; port: int;
                       sockType: cint): Future[seq[Sockaddr_storage]] =
  ## Awaitable address resolution on the caller's `loop`. The caller must keep
  ## driving `loop` (e.g. it is already `run()`ning) until the future completes.
  ## Numeric IP literals, `/etc/hosts` hits and warm-cache hits complete
  ## immediately without any DNS I/O.
  let fut = newFuture[seq[Sockaddr_storage]]()
  resolveAddr(loop, address, port, sockType,
    proc(addrs: seq[Sockaddr_storage]; err: string) =
      if not fut.finished:
        if err.len > 0:
          fut.fail(newException(DnsError, err))
        else:
          fut.complete(addrs))
  fut

proc resolveAddrAsync*(address: string; port: int;
                       sockType: cint): Future[seq[Sockaddr_storage]] =
  ## Self-contained awaitable resolution with an internal event loop.
  ## `await resolveAddrAsync("example.com", 443, SOCK_STREAM)` — the loop is
  ## closed before the future completes.
  let fut = newFuture[seq[Sockaddr_storage]]()
  if isIpAddress(address):
    try:
      fut.complete(@[sockaddrFromIp(address, port)])
    except NetError as e:
      fut.fail(newException(DnsError, e.msg))
    return fut
  let h = getHosts().getOrDefault(address.toLowerAscii())
  if h.len > 0:
    var outAddrs: seq[Sockaddr_storage]
    for ip in h:
      outAddrs.add(makeSockaddr(ip, port))
    fut.complete(outAddrs)
    return fut
  let loop = newLoop()
  var done = false
  var outAddrs: seq[Sockaddr_storage]
  var outErr = ""
  resolveAddr(loop, address, port, sockType,
    proc(addrs: seq[Sockaddr_storage]; err: string) =
      outAddrs = addrs
      outErr = err
      done = true)
  proc pump() {.async.} =
    ## Drive the private loop in lockstep with the asyncdispatch dispatcher
    ## until the query settles (same pattern as `AsyncHttpClient.request`).
    while not done:
      loop.poll(0)
      if not done:
        await sleepAsync(1)
    loop.close()
    if outErr.len > 0:
      fut.fail(newException(DnsError, outErr))
    else:
      fut.complete(outAddrs)
  discard pump()
  fut

proc resolveMxAsync*(loop: Loop; domain: string): Future[seq[MxRecord]] =
  ## Awaitable MX resolution on the caller's `loop` (see `resolveAddrAsync`).
  ## An empty result with no error means the name exists but publishes no MX
  ## (RFC 5321 §5.1 fallback applies); NXDOMAIN/timeout raise `DnsError`.
  let fut = newFuture[seq[MxRecord]]()
  resolveMx(loop, domain,
    proc(mxs: seq[MxRecord]; err: string) =
      if not fut.finished:
        if err.len > 0:
          fut.fail(newException(DnsError, err))
        else:
          fut.complete(mxs))
  fut

proc resolveMxAsync*(domain: string): Future[seq[MxRecord]] =
  ## Self-contained awaitable MX resolution with an internal event loop.
  let fut = newFuture[seq[MxRecord]]()
  let loop = newLoop()
  var done = false
  var outMxs: seq[MxRecord]
  var outErr = ""
  resolveMx(loop, domain,
    proc(mxs: seq[MxRecord]; err: string) =
      outMxs = mxs
      outErr = err
      done = true)
  proc pump() {.async.} =
    while not done:
      loop.poll(0)
      if not done:
        await sleepAsync(1)
    loop.close()
    if outErr.len > 0:
      fut.fail(newException(DnsError, outErr))
    else:
      fut.complete(outMxs)
  discard pump()
  fut

proc resolveTxtAsync*(loop: Loop; hostname: string): Future[seq[TxtRecord]] =
  ## Awaitable TXT resolution on the caller's `loop` (see `resolveAddrAsync`).
  let fut = newFuture[seq[TxtRecord]]()
  resolveTxt(loop, hostname,
    proc(txts: seq[TxtRecord]; err: string) =
      if not fut.finished:
        if err.len > 0:
          fut.fail(newException(DnsError, err))
        else:
          fut.complete(txts))
  fut

proc resolveTxtAsync*(hostname: string): Future[seq[TxtRecord]] =
  ## Self-contained awaitable TXT resolution with an internal event loop.
  let fut = newFuture[seq[TxtRecord]]()
  let loop = newLoop()
  var done = false
  var outTxts: seq[TxtRecord]
  var outErr = ""
  resolveTxt(loop, hostname,
    proc(txts: seq[TxtRecord]; err: string) =
      outTxts = txts
      outErr = err
      done = true)
  proc pump() {.async.} =
    while not done:
      loop.poll(0)
      if not done:
        await sleepAsync(1)
    loop.close()
    if outErr.len > 0:
      fut.fail(newException(DnsError, outErr))
    else:
      fut.complete(outTxts)
  discard pump()
  fut

proc resolveAddrBothAsync*(loop: Loop; address: string; port: int):
    Future[seq[Sockaddr_storage]] =
  ## Awaitable dual-family resolution on the caller's `loop`: all socket
  ## addresses ordered IPv6-first (RFC 8305 family-block order). If one family
  ## fails the other is still delivered; both empty raises `DnsError`.
  let fut = newFuture[seq[Sockaddr_storage]]()
  resolveAddrBoth(loop, address, port,
    proc(addrs: seq[Sockaddr_storage]; err: string) =
      if not fut.finished:
        if err.len > 0:
          fut.fail(newException(DnsError, err))
        else:
          fut.complete(addrs))
  fut

proc resolveAddrBothAsync*(address: string; port: int):
    Future[seq[Sockaddr_storage]] =
  ## Self-contained awaitable dual-family resolution with an internal loop.
  let fut = newFuture[seq[Sockaddr_storage]]()
  if isIpAddress(address):
    try:
      fut.complete(@[sockaddrFromIp(address, port)])
    except NetError as e:
      fut.fail(newException(DnsError, e.msg))
    return fut
  let h = getHosts().getOrDefault(address.toLowerAscii())
  if h.len > 0:
    var outAddrs: seq[Sockaddr_storage]
    for ip in h:
      outAddrs.add(makeSockaddr(ip, port))
    fut.complete(outAddrs)
    return fut
  let loop = newLoop()
  var done = false
  var outAddrs: seq[Sockaddr_storage]
  var outErr = ""
  resolveAddrBoth(loop, address, port,
    proc(addrs: seq[Sockaddr_storage]; err: string) =
      outAddrs = addrs
      outErr = err
      done = true)
  proc pump() {.async.} =
    while not done:
      loop.poll(0)
      if not done:
        await sleepAsync(1)
    loop.close()
    if outErr.len > 0:
      fut.fail(newException(DnsError, outErr))
    else:
      fut.complete(outAddrs)
  discard pump()
  fut
