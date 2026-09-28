---
title: Async DNS
description: "The in-loop RFC 1035 DNS resolver: no blocking getaddrinfo, hosts/resolv.conf support, TTL caching and retries."
keywords: ["powpow", "dns", "resolver", "async", "rfc1035"]
---

# Async DNS

`net/dns.nim` implements an in-loop DNS resolver (RFC 1035). Name resolution
runs entirely on the powpow event loop — no blocking `getaddrinfo`, no worker
threads, no `--threads:on` requirement. `tcp.connect` uses it automatically, so
outbound connects never stall the loop on DNS.

Status: implemented (see [`plans/async_dns.md`](../../plans/async_dns.md) for the
design and the follow-up work).

## How it works

- One non-blocking UDP socket owned by the loop; inbound datagrams are matched
  to queries by randomized query id.
- Sends A + AAAA queries with A-fallback; retries across nameservers with
  `timeout`/`attempts` taken from `resolv.conf` (defaults 5s / 2).
- Reads `/etc/hosts` (IP + aliases, cached) and `/etc/resolv.conf`
  (`nameserver` entries). On macOS the stub `127.0.0.1` resolv.conf works
  (mDNSResponder handles it). Falls back to `8.8.8.8` / `1.1.1.1`.
- TTL-based positive cache plus a short (30s) negative cache for NXDOMAIN.
- Numeric IP literals resolve inline with zero DNS I/O.

## Resolving an address

```nim
resolveAddrAsync(loop, "example.com", port = 443, SOCK_STREAM,
  proc(addrs: seq[Sockaddr_storage]; err: string) =
    if err.len > 0:
      echo "resolution failed: ", err
    else:
      echo "resolved to ", addrs.len, " address(es)"))
```

The callback fires with a sequence of `Sockaddr_storage` results (IPv4 and
IPv6), or a non-empty `err`. The callback runs on the loop.

`DnsCallback = proc(addrs: seq[Sockaddr_storage]; err: string) {.closure.}`

## Configuring the resolver

```nim
configureDns(loop, timeoutMs = 3000, attempts = 3)       # retry policy
setDnsServers(loop, [("8.8.8.8", 53), ("1.1.1.1", 53)])  # override servers
closeDns(loop)                                            # free the resolver
```

## Integration with TCP connect

`tcp.connect` resolves the hostname on the loop before opening the socket, and
reports DNS failure through its `onError` callback:

```nim
connect(loop, "api.example.com", 443,
  onConnect = proc(conn: Connection) = echo "connected",
  onData = proc(conn: Connection, data: openArray[byte]) = discard,
  onError = proc(err: string) = echo "connect/DNS failed: ", err)
```

## Not yet implemented (roadmap)

- TCP fallback for truncated responses
- Search domains / `ndots` from `resolv.conf`
- IPv6 nameservers with scope IDs
- UDP `sendTo` sync cache fast-path

See [`plans/roadmap.md`](../../plans/roadmap.md).

## API reference

Full signatures: [DNS API](../api/dns.md).
