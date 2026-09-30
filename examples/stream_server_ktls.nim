## examples/stream_server_ktls.nim — streaming + downloads over TLS with kTLS.
##
## The streaming variant of `stream_server.nim`, with two differences that
## matter once the bytes are encrypted:
##
## - **File sends can be zero-copy.** `sendFile` / `serveFile` end up in
##   `sendfile(2)`, handing page-cache pages straight to the socket. That is
##   only possible when the *kernel* is doing the encrypting, so it needs kTLS
##   TX offload. Without it powpow transparently falls back to reading the
##   file and `SSL_write`-ing 64 KiB chunks — same bytes, fewer syscalls than
##   a `read`/`write` loop, but the data does pass through userspace.
## - **Media streaming is different.** `streamFile` caps each response to one
##   chunk so a seek transfers a chunk rather than the whole file, which means
##   it rarely benefits from `sendfile` and is happy either way. It is
##   included here to show the same route working in both modes.
##
## Run:
##   sudo modprobe tls            # kTLS lives in a separate kernel module
##   nim c -r examples/stream_server_ktls.nim
##
## Test:
##   curl -k https://localhost:9445/ktls
##   curl -k -o /dev/null -w '%{speed_download} B/s\n' https://localhost:9445/download
##   curl -k -o /dev/null -w '%{speed_download} B/s\n' -H 'Range: bytes=0-1048575' \
##     https://localhost:9445/video
##
## The kTLS win is easiest to see with `strace -f -e trace=sendfile,read`:
## with offload engaged the transfer is all `sendfile` and there are no
## `read` calls on the file descriptor at all.

import ../src/powpow
import ./devcert
import std/httpcore except HttpMethod
import std/[os, strutils]

const KtlsStreamPort = 9445

# Big Buck Bunny, 4K, ~2.76 GB: https://en.wikipedia.org/wiki/File:Big_Buck_Bunny_4K.webm
# stream_server.nim streams the file checked in next to it; do the same so the
# two examples can be compared directly. Any large local file works.
let mediaPath = getCurrentDir() / "Big_Buck_Bunny_4K.webm"

let (certPath, keyPath) = writeDevCert("powpow-devcert-stream")

let server = newHttpServer()
let sslCtx = newServerTlsContext(certPath, keyPath)

# Ask the kernel to terminate TLS. Best-effort, and a no-op wherever kTLS does
# not exist: offload is a Linux kernel feature, so on macOS/BSD — and under
# the io_uring backend, which runs TLS over memory BIOs — this is skipped and
# powpow's ordinary userspace TLS handles everything instead. Nothing below
# branches on it, which is the point.
if ktlsSupported():
  sslCtx.configureKtls(KtlsAuto, zerocopySendfile = true)
server.sslCtx = sslCtx

proc handler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  {.gcsafe.}:
    let path = req.getPath()

    if path == "/video":
      # Media streaming: one capped chunk per response, Range-aware, and
      # keep-alive so a player can seek without reconnecting.
      res.streamFile(mediaPath, req)

    elif path == "/download":
      # Whole-file download with Content-Disposition. This is the one that
      # really wants kTLS: with TX offload the bytes go out via sendfile(2)
      # and never enter userspace.
      res.sendFile(mediaPath, req, closeConn = false)

    elif path == "/resume":
      # Resume-aware static serving: ETag, If-Modified-Since, If-Range and
      # Range all handled for you (304 when unchanged, 206 for a range).
      discard res.serveFile(req, mediaPath, attach = true)

    elif path == "/ktls":
      # Whether *this* connection is offloaded — the only question that
      # decides if the file routes above can use sendfile(2).
      res.status(Http200)
        .header("Content-Type", "text/plain; charset=utf-8")
        .send("kernel TLS offload: " & $res.ktlsActive() & "\n" &
              "  kernel can offload:  " & $ktlsSupported() & "\n" &
              "  transmit offloaded:   " & $res.ktlsTxActive() & "\n" &
              "  media file:           " &
                (if fileExists(mediaPath): mediaPath else: "(missing)") & "\n")

    else:
      res.sendError(Http404, "Not Found: " & path)

echo "⚡ powpow HTTPS + kTLS streaming server on https://localhost:" & $KtlsStreamPort
if ktlsSupported():
  echo "  kTLS available — file sends will use sendfile(2) on the TLS socket"
else:
  echo "  kTLS unavailable (is the `tls` module loaded?) — falling back to"
  echo "  userspace TLS; streaming still works, just not zero-copy"
if not fileExists(mediaPath):
  echo "  note: " & mediaPath & " not found — the file routes will 404."
  echo "  any large local file works; edit mediaPath at the top of this example"
echo "  Try:  curl -k https://localhost:" & $KtlsStreamPort & "/ktls"
echo "  Press Ctrl+C to stop"
server.start(handler, Port(KtlsStreamPort))
