## examples/httpserver_ktls.nim — HTTPS server with kernel-TLS (kTLS) offload.
##
## Same shape as `tls_server.nim`, but asks the kernel to terminate TLS
## instead of doing the record layer in userspace. Two things change when the
## offload engages:
##
## - File bodies go out via a real `sendfile(2)` onto the TLS socket. Only a
##   kernel-encrypted socket may be handed raw file bytes, so without offload
##   powpow falls back to reading the file and `SSL_write`-ing 64 KiB chunks.
##   That fallback is automatic and always correct — the offload is purely a
##   throughput/latency win, never a behaviour change.
## - `res.ktlsOffload()` reports where the records actually terminate, so you
##   can confirm the win instead of assuming it.
##
## Run:
##   sudo modprobe tls            # kTLS lives in a separate kernel module
##   nim c -r examples/httpserver_ktls.nim
##
## Test:
##   curl -k https://localhost:9444/hello
##   curl -k https://localhost:9444/ktls
##   curl -k -o /dev/null -w '%{speed_download}\n' \
##     https://localhost:9444/download
##
## Try `KtlsRequired` instead of `KtlsAuto` to make a machine that cannot
## offload (no `tls` module, a libssl built without `enable-ktls`, an
## unsupported cipher) fail loudly at connect time rather than quietly
## serving every byte in userspace.

import ../src/powpow
import ./devcert
import std/httpcore except HttpMethod
import std/[os, strutils]

const KtlsPort = 9444

let (certPath, keyPath) = writeDevCert()

# A file to exercise the zero-copy path. A few MiB is enough to see the
# difference; point this at something bigger for a real comparison.
let payloadPath = getCurrentDir() / "bigfile.bin"
if not fileExists(payloadPath):
  writeFile(payloadPath, repeat('k', 8 * 1024 * 1024))

let server = newHttpServer()
let sslCtx = newServerTlsContext(certPath, keyPath)

# Ask OpenSSL to move the record layer into the kernel. `KtlsAuto` is
# best-effort — the handshake succeeds either way. `zerocopySendfile` adds
# SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE, which lets a capable NIC skip the
# in-kernel copy entirely (the file must not be modified mid-transfer).
#
# Only ask when the kernel can actually do it. Offload is a Linux kernel
# feature, so on macOS/BSD (and under the io_uring backend, which drives TLS
# through memory BIOs) this is skipped and powpow's ordinary userspace TLS
# handles everything — same code path, same behaviour, no special casing
# anywhere below.
if ktlsSupported():
  sslCtx.configureKtls(KtlsAuto, zerocopySendfile = true)
server.sslCtx = sslCtx

server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  {.gcsafe.}:
    let path = req.getPath()

    if path == "/hello":
      res.status(Http200)
        .header("Content-Type", "text/plain; charset=utf-8")
        .send("hello over TLS!\n")

    elif path == "/ktls":
      # Per-connection introspection: did *this* socket actually offload?
      # "did we ask for it" and "did the kernel do it" are different
      # questions, and only the second one unlocks the fast path.
      res.status(Http200)
        .header("Content-Type", "text/plain; charset=utf-8")
        .send("kernel TLS offload: " & $res.ktlsActive() & "\n" &
              "  kernel can offload:  " & $ktlsSupported() & "\n" &
              "  transmit offloaded:   " & $res.ktlsTxActive() & "\n")

    elif path == "/download":
      # serveFile -> sendFile -> sendfile(2). With kTLS TX engaged this
      # streams the file straight off the page cache into the socket with
      # the kernel framing the TLS records; without it, a 64 KiB
      # read + SSL_write loop.
      discard res.serveFile(req, payloadPath, contentType = "application/octet-stream")

    else:
      res.sendError(Http404, "404 Not Found: " & path)

echo "⚡ HTTPS + kTLS server listening on https://localhost:" & $KtlsPort
if ktlsSupported():
  echo "  kernel can offload TLS — is the `tls` module loaded"
else:
  echo "  kernel CANNOT offload TLS (is the `tls` module loaded?)"
  echo "  run `sudo modprobe tls`; requests still work, via userspace TLS"
echo "  Test with:  curl -k https://localhost:" & $KtlsPort & "/ktls"
echo "  Press Ctrl+C to stop"
server.start(server.handler, Port(KtlsPort))
