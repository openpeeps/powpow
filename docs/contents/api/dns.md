---
title: dns
description: "The async DNS resolver API: resolveAddrAsync, configureDns, setDnsServers and closeDns."
keywords: ["powpow", "api", "dns", "resolver", "resolveaddrasync"]
---

# dns

In-loop DNS resolver (RFC 1035). Source: `src/powpow/net/dns.nim`.
Guide: [Async DNS](../core/dns.md).

## Types

```nim
DnsCallback* = proc(addrs: seq[Sockaddr_storage]; err: string) {.closure.}
DnsResolver* = ref object of RootObj    # internal state
```

## Procs

```nim
proc resolveAddrAsync*(loop: Loop; address: string; port: int;
                       sockType: cint;
                       cb: proc(addrs: seq[Sockaddr_storage]; err: string) {.closure.})
proc configureDns*(loop: Loop; timeoutMs: int; attempts: int)
proc setDnsServers*(loop: Loop; servers: openArray[(string, int)])
proc closeDns*(loop: Loop)
```

## Related

- [common](common.md) — `Sockaddr_storage`, `isIpAddress`, `sockaddrFromIp`
- [tcp](tcp.md) — `connect` resolves hostnames via this resolver
