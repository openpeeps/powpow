# HTTP/2

Experimental HTTP/2 support ([RFC 7540](https://httpwg.org/specs/rfc7540.html))
with full [HPACK](https://httpwg.org/specs/rfc7541.html), built on the same
event loop and TCP/TLS transport as the HTTP/1.1 server. Verified against
real clients (curl/nghttp2): prior-knowledge `h2c`, `Upgrade: h2c`, and
`h2` over TLS with ALPN.

## Negotiation matrix

| Client sends | Server port | Result |
|---|---|---|
| `PRI * HTTP/2.0…` + SETTINGS (prior knowledge) | `newH2Server` (h2c) | H2 session |
| `GET` + `Upgrade: h2c` + `HTTP2-Settings` | `newH2Server` (h2c) | `101 Switching Protocols`, then H2; request becomes stream 1 |
| Plain H1 without upgrade | `newH2Server` (h2c) | `426 Upgrade Required` + close |
| TLS + ALPN `h2` | `newH2Server(sslCtx = …)` | H2 session |
| TLS + anything else | `newH2Server(sslCtx = …)` | Closed after the handshake (h2-only port) |

## Server

```nim
import powpow
import powpow/proto/http2conn

let loop = newLoop()
let srv = newH2Server(loop) do (req: H2Request, res: H2Response):
  res.header("content-type", "text/plain").send("hello " & req.path)
srv.listen("127.0.0.1", 9000)
loop.run()
```

With TLS (`h2`):

```nim
import powpow/net/tls

let ctx = newServerTlsContext("cert.pem", "key.pem")  # advertises ALPN `h2`
let srv = newH2Server(loop, handler, sslCtx = ctx)
```

Responses use `res.status(code).header(name, value).send(body)`; `res.reset()`
aborts a stream. Oversize header blocks get an automatic `431`.

## Client

`H2ClientConn` multiplexes many concurrent requests over one connection,
each with its own callback:

```nim
import powpow/proto/http2client

connectH2(loop, "127.0.0.1", 9000) do (c: H2ClientConn, err: string):
  c.request("GET", "/", [], "", proc(resp: H2ClientResponse, err: string) =
    echo resp.status, " body=", resp.body.len
  )
```

`H2ClientPool` shares connections per origin (`host, port, tls`) with
least-loaded routing and bounded fan-out (`maxPerOrigin`); overflow waits
instead of opening more connections.

## Limits and knobs

`newH2Server(loop, handler, maxConcurrent = 128, maxHeaderList = 16384,
maxBody = 8 * 1024 * 1024)`:

- `maxConcurrent` — streams beyond it are refused with `RST_STREAM(REFUSED)`.
- `maxHeaderList` — decoded header lists beyond it get `431`.
- `maxBody` — request/response bodies beyond it are refused with
  `RST_STREAM(CANCEL)`.

Flow control follows the spec on both levels (64 KiB windows with
`WINDOW_UPDATE` top-ups); DATA is chunked to the peer's max frame size and
queued behind open windows. SETTINGS understood: `HEADER_TABLE_SIZE`
(caps our HPACK encoder), `INITIAL_WINDOW_SIZE`, `MAX_FRAME_SIZE`,
`MAX_CONCURRENT_STREAMS`. `ENABLE_PUSH` is accepted and ignored — server
push (`PUSH_PROMISE`) is a connection error, as is any `PRIORITY`
scheduling beyond validation.

## I/O backends

HTTP/2 rides the existing `Connection.send` path, so it works unchanged on
the default readiness backends (epoll/kqueue) and the guarded io_uring
backend (`-d:powpowIoUring`): frame writes use the same `SEND`/`SEND_ZC`
and `SPLICE` pumps as HTTP/1.1, and TLS uses the same memory-BIO layer.
Multiplexed streams sharing one TCP connection are exactly the workload
io_uring parallelism suits best (see [performance](../performance.md)).

## Current boundaries

- H2 API is native (`H2Request`/`H2Response`); sharing the H1
  `OnRequestCallback` is future work.
- No server push, no weighted priority scheduling.
- Request bodies are buffered (bounded by `maxBody`); no trailers API yet
  (trailing `HEADERS` merge into the header list).
- Graceful `GOAWAY` drain serves in-flight streams on receipt; `close()`
  is abrupt (GOAWAY + TCP close).
