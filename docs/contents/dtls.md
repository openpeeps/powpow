---
title: DTLS
description: "DTLS 1.2 (RFC 6347) in powpow: encrypted UDP with per-peer sessions, stateless cookie exchange, retransmission timers, and DoS caps."
keywords: ["powpow", "dtls", "udp", "tls", "openssl", "security"]
---

# DTLS

`net/dtls.nim` adds DTLS 1.2 (RFC 6347) on top of the UDP backend. One bound
socket multiplexes every peer; each peer's handshake state lives in a
`DtlsSession` keyed by its network address. Handshakes run over memory BIOs
(the same driver the io_uring TLS path uses), so the module is
transport-agnostic: it works unchanged on kqueue/epoll/IOCP readiness loops and
on the io_uring backend.

## Server

```nim
import powpow

let loop = newLoop()
let ctx = newServerDtlsContext("cert.pem", "key.pem")   # PEM pair, DTLS 1.2

let srv = newDtlsServer(loop, "0.0.0.0", 4433, ctx) do (sess: DtlsSession, data: openArray[byte]):
  discard sess.send(data)          # echo

loop.run()
```

Callbacks are also available as named parameters:

```nim
let srv = newDtlsServer(loop, "0.0.0.0", 4433, ctx,
  onData          = proc(sess: DtlsSession; data: openArray[byte]) =
    echo "got ", data.len, " plaintext bytes"
  ,
  onHandshakeDone = proc(sess: DtlsSession) =
    echo "peer up: ", sess.peerAddrStr()
  ,
  onClose         = proc(sess: DtlsSession) =
    discard)
```

A session is created only when an inbound datagram looks like a DTLS
ClientHello — random garbage never allocates OpenSSL state.

## Client

```nim
let ctx = newClientDtlsContext(verifyPeer = false)   # self-signed test servers
let cli = connectDtls(loop, "127.0.0.1", 4433, ctx,
  onData          = proc(sess: DtlsSession; data: openArray[byte]) =
    echo "reply: ", cast[string](@data)
  ,
  onHandshakeDone = proc(sess: DtlsSession) =
    discard sess.send("hello"))

discard cli.send("later message")
```

`connectDtls` sends the ClientHello immediately; `send()` before the handshake
completes returns `-1`.

## Stateless cookie exchange (DoS mitigation)

Servers require a HelloVerifyRequest cookie **by default** before any
handshake crypto is committed. The cookie is HMAC-SHA256 over the peer's
address bytes using a per-context random secret (`RAND_bytes`) — nothing is
stored, so spoofed-address floods cannot consume memory or CPU beyond one
short datagram per attempt.

Disable it for closed networks where every client is known:

```nim
let ctx = newServerDtlsContext("cert.pem", "key.pem", cookieExchange = false)
```

OpenSSL clients handle the extra round trip transparently.

## Resource caps

All knobs live in `DtlsConfig`; pass it to `newDtlsServer(..., config = cfg)`:

| Field | Default | Meaning |
|---|---|---|
| `maxSessions` | 1024 | Hard cap on concurrent sessions; further ClientHellos are ignored |
| `handshakeTimeoutMs` | 10_000 | Sweeper reaps sessions stuck mid-handshake |
| `idleTimeoutMs` | 120_000 | Sweeper reaps active sessions idle this long |
| `mtu` | 1400 | Link MTU hint used for record sizing |
| `cookieExchange` | true | Require the stateless cookie round |
| `sweepIntervalMs` | 5_000 | Sweeper period (0 disables sweeping) |

UDP has no FIN: without the sweeper, vanished peers would leak sessions
forever. Keep `idleTimeoutMs` finite for anything internet-facing.

## Sending data — what to expect

- `sess.send(data)` accepts at most ~1.35 KiB *per DTLS message* internally;
  larger payloads are split into MTU-sized messages automatically and the
  peer reassembles them across successive `onData` callbacks (ordered,
  stream-like). This avoids OpenSSL's 16 KiB single-message cap and keeps
  datagrams inside typical path MTUs so they are not truncated by receivers.
- Datagrams are atomic but **not acknowledged**: if the network drops one,
  that slice of application data is lost. Reliability belongs above DTLS
  (CoAP-style retransmits, QUIC, ...) — this matches how DTLS is used in the
  wild.
- While the socket send buffer is full, records stay queued and flush on a
  short internal retry timer; `send` then reports only the accepted prefix
  (or `0`) rather than blocking.

## Platform support

POSIX only (macOS, Linux, BSD) — same policy as TLS. On Windows every call
raises `DtlsError`. Requires OpenSSL ≥ 1.1.0 linked at compile time
(`-lssl -lcrypto`), identical to `net/tls.nim`.
