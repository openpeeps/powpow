---
title: Kernel TLS (kTLS)
description: "Opt-in kernel-TLS offload for powpow on Linux: moving the TLS record layer out of userspace so file sends reach a real sendfile(2) on the TLS socket."
keywords: ["powpow", "ktls", "kernel tls", "linux", "offload", "sendfile", "zero-copy", "openssl", "tls"]
---

# Kernel TLS (kTLS)

powpow's [TLS](tls.md) runs the record layer in **userspace**: every byte is
encrypted by OpenSSL and copied into the socket. kTLS is the Linux kernel
feature that moves that record layer *into the kernel*, so a connected socket
encrypts and decrypts on its own.

That sounds like a small win for CPU. The reason powpow supports it is one
step further down the stack:

> **A socket the kernel encrypts can be handed raw file bytes.**
> `sendfile(2)` writes page-cache pages straight into the socket, and the
> kernel frames the TLS records on the way out. The file never enters
> userspace — no `read`, no `SSL_write`, no 64 KiB bounce buffer.

So for a server serving large files, kTLS is the difference between

```
read(fd, buf, 64K)  ->  SSL_write(sock, buf)  ->  send(sock, ...)
```

and

```
sendfile(fd, sock, offset, count)     # once per EAGAIN
```

Without offload, `sendFile` refuses the transfer outright and `serveFile` /
`sendFile` fall back to the chunk loop — same bytes on the wire, more copies.
With offload, verified with `strace -f -e trace=sendfile,read`, the transfer
is `sendfile()` and there are **zero `read()` calls** on the file descriptor.

> [!IMPORTANT]
> kTLS is a **Linux kernel feature**. On macOS, the BSDs and Windows it does
> not exist, and powpow uses userspace TLS there — the same `sslCtx`, the same
> handlers, the same bytes. Offload is never load-bearing.

## Requirements

All four must hold. Any one missing and powpow stays in userspace TLS, with no
error and no behaviour change.

| Requirement | Why |
| --- | --- |
| Linux `tls` module loaded (`sudo modprobe tls`) | The record layer ULP is a separate module, not built in |
| OpenSSL ≥ 3.0 built with `enable-ktls` | OpenSSL drives the key installation; without it `SSL_OP_ENABLE_KTLS` is inert |
| A kTLS-capable negotiated cipher | AES-GCM, AES-CCM and ChaCha20-Poly1305; everything else stays in userspace |
| A **socket-BIO** backend | The epoll/kqueue readiness loop. The [io_uring](../io_uring.md) backend runs TLS over memory BIOs, where OpenSSL never sees the fd and cannot offload |

`modprobe` is not persistent across reboots. To make it stick:

```bash
echo tls | sudo tee /etc/modules-load.d/tls.conf
```

## Enabling it

```nim
import powpow

let server = newHttpServer()
let sslCtx = newServerTlsContext("cert.pem", "key.pem")

# Ask the kernel to terminate TLS, and let a capable NIC skip the
# in-kernel copy entirely. The file must not change mid-transfer.
sslCtx.configureKtls(KtlsAuto, zerocopySendfile = true)
server.sslCtx = sslCtx
```

`configureKtls` replaces the older one-way `enableKtls` flag. Call it before
wrapping connections; it applies to every `SSL*` that `wrapTls` creates
afterwards.

### KtlsMode

```nim
KtlsOff        ## default — never request offload
KtlsAuto       ## request it, fall back silently
KtlsRequired   ## request it, drop connections where it did not engage
```

`KtlsAuto` is the safe default: the handshake is identical either way, and the
fallback is invisible to your code.

`KtlsRequired` is for deployments where "kTLS is on" is a property you are
*asserting* rather than hoping for. A missing `tls` module, a libssl built
without `enable-ktls` or an unsupported cipher becomes a **dropped
connection** instead of a permanently slower server that still looks healthy.
The connection is closed before any application data goes out, so nothing is
ever served in userspace crypto on a connection you believe is offloaded.

`disableKtls(ctx)` is the inverse of `enableKtls`; connections already wrapped
keep the state they negotiated.

## Asking what actually happened

"Did we ask for offload" and "did the kernel do it" are different questions,
and only the second one unlocks `sendfile(2)`. Offload is negotiated per
connection and can legitimately fail on any given one.

```nim
# Is offload possible at all on this machine? (kernel capability)
ktlsSupported(): bool

# Per-connection, read from the kernel:
conn.ktlsTxActive()   ## kernel encrypts the transmit path -> sendfile works
conn.ktlsRxActive()   ## kernel decrypts the receive path
conn.ktlsActive()     ## either direction

# Same for an HTTP response:
res.ktlsActive()
res.ktlsTxActive()
```

`ktlsSupported()` is necessary but not sufficient — it only reports the kernel
half. A live connection can still not offload, so log the per-connection
answer if you care:

```nim
proc handler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  {.gcsafe.}:
    if not res.ktlsActive():
      echo "userspace TLS: ", req.clientIp
    discard res.serveFile(req, path, req)
```

## A complete example

```nim
import powpow

let server = newHttpServer()
let sslCtx = newServerTlsContext("cert.pem", "key.pem")
sslCtx.configureKtls(KtlsAuto, zerocopySendfile = true)
server.sslCtx = sslCtx

server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  {.gcsafe.}:
    case req.getPath()
    of "/ktls":
      res.status(Http200).send(
        "offload: " & $res.ktlsActive() &
        "  transmit: " & $res.ktlsTxActive())
    of "/download":
      discard res.serveFile(req, "/var/www/movie.mp4")
    else:
      res.sendError(Http404)

server.start(server.handler, Port(9444))
```

Runnable versions:

- [`examples/httpserver_ktls.nim`](../../examples/httpserver_ktls.nim) — HTTPS
  with a `/ktls` endpoint reporting per-connection offload state.
- [`examples/stream_server_ktls.nim`](../../examples/stream_server_ktls.nim) —
  the streaming and download routes of
  [`examples/stream_server.nim`](../../examples/stream_server.nim) over TLS.

Both ask for offload only when `ktlsSupported()` and never branch on the
answer, so they are ordinary userspace-TLS servers everywhere kTLS does not
exist.

## Which routes actually benefit

| Route | Path to the wire | Benefit |
| --- | --- | --- |
| `serveFile` / `sendFile` | `sendfile(2)` with offload | **The whole point** — file never enters userspace |
| `streamFile` | capped chunks, keep-alive | Little. Caps each response to one chunk, so there is rarely much to send |
| `res.send` / `sendv` | `SSL_write` | CPU only — encryption leaves userspace |
| WebSocket, HTTP/2 | `SSL_write` | CPU only |

Worth being blunt about: for a request/response API, kTLS is a CPU
optimisation. It is only *structurally* different for file serving, and only
on Linux with the right kernel and libssl.

## Verifying it yourself

The offload is invisible in the output, so measure it rather than assume it.
With offload engaged, the transfer should be all `sendfile` and no `read` on
the file descriptor:

```bash
strace -f -e trace=sendfile,read -o trace.log ./httpserver_ktls &
curl -k -o /dev/null https://localhost:9444/download
grep -c sendfile trace.log   # > 0
grep -c ' read(' trace.log   # 0 — the file never enters userspace
```

The test suite takes the same stance. `tests/test_ktls.nim` checks that the
answers are self-consistent, and additionally that a plain socket never claims
offload. That consistency check alone is not enough — it is exactly what a
probe stuck permanently at "off" satisfies — so:

```bash
POWPOW_KTLS_STRICT=1 nimble test      # or: clue test test_ktls
```

tightens it to *offload actually engaged*, which is what catches a probe that
has drifted. It requires a kernel with the `tls` module loaded and a libssl
built with `enable-ktls`; CI already runs `sudo modprobe tls` on Linux.

## How the state is read

Worth knowing if you are debugging, because the obvious approaches do not
work. kTLS is a ULP under `SOL_TCP`, and the option numbers it uses share a
namespace with the ordinary TCP options.

The state is read in two steps (`net/common.nim`):

1. `getsockopt(SOL_TCP, TCP_ULP, ...)` to confirm the `tls` ULP is actually
   attached — a zero length means it is not. This step is not optional.
2. `getsockopt(SOL_TLS, TLS_TX | TLS_RX, ...)` for the direction. The kernel
   validates the buffer length against the *negotiated cipher's*
   `tls12_crypto_info_*` struct, so the read is offered at 56 bytes and then
   40 — the only two sizes that exist.

The 1-byte `TLS_INFO_TXCONF` / `TLS_INFO_RXCONF` options look like the natural
way to ask this and are not usable: `TLS_INFO_TXCONF` reads back 0 on a socket
with keys installed, and `TLS_INFO_RXCONF` is the same number as
`TCP_KEEPIDLE`, so on a socket with no ULP attached the kernel answers from the
keepalive path and returns a confident-looking non-zero byte.

That last case is why powpow's own constants are asserted against the kernel
headers at C compile time. A wrong number there does not fail — it silently
answers from a neighbouring TCP option, and a false "engaged" hands raw file
bytes to a kernel that is not encrypting them.

## API reference

`KtlsMode`, `configureKtls`, `enableKtls`, `disableKtls`, `ktlsSupported`,
`ktlsTxActive`, `ktlsRxActive`, `ktlsActive`, `ktlsTxInstalled`,
`ktlsRxInstalled` — see [TLS](tls.md) for the surrounding API, and
[TLS API](../api/tls.md) for full signatures.

Related: [TLS](tls.md) · [static files](../http/static-files.md) ·
[io_uring](../io_uring.md) · [performance](../performance.md)
