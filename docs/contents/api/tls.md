---
title: tls
description: "The TLS API: SslContext, newServerTlsContext, newClientTlsContext, wrapTls and isTlsActive."
keywords: ["powpow", "api", "tls", "ssl", "context"]
---

# tls

OpenSSL TLS over powpow `Connection`s. Source: `src/powpow/net/tls.nim`.
Guide: [TLS](../net/tls.md). Not supported on Windows (raises `SslError`).

## Enum

```nim
TlsRole* = enum TlsServer, TlsClient
```

## Types

```nim
SslContext* = ref object          # opaque: ctx + role
SslError* = object of CatchableError
```

## Procs

```nim
proc newServerTlsContext*(certFile, keyFile: string): SslContext
proc newClientTlsContext*(verifyPeer = true): SslContext
proc wrapTls*(conn: Connection, ctx: SslContext, serverName = "")
proc isTlsActive*(conn: Connection): bool {.inline.}
```

## Related

- [tcp](tcp.md) — `driveHandshake`, `tlsRead`, `tlsWrite`, `tlsFree`
- [tlsapi](tlsapi.md) — the underlying OpenSSL bindings
