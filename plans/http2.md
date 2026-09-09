# HTTP/2 (RFC 7540) Plan — `feature/http2` branch

Spec: https://httpwg.org/specs/rfc7540.html
Companion: RFC 7541 (HPACK)
Date: 2026-09-09
Branch: `feature/http2` from `main`

## Scope (locked)

- Server + client
- h2 (TLS with ALPN) + h2c (prior knowledge + Upgrade)
- Full HPACK (RFC 7541) — static + dynamic table + Huffman
- Defer PUSH_PROMISE and strict priority scheduling
- epoll default on Linux, io_uring guarded under existing `-d:powpowIoUring` / `features.powpow.io_uring` flag

## 0. Branch and baseline audit

- Create `feature/http2` from `main`. No H1 behavior changes on `main`.
- Reconcile contradiction: `plans/pre-http2.md:21` claims ALPN done, but grep shows no `SSL_CTX_set_alpn_protos` / `SSL_get0_alpn_selected` in `src/powpow/net/tlsapi.nim` and `tls.nim`. Treat ALPN as not done until verified.
- Confirm H1 gates actually landed: chunked trailers (`proto/http.nim`), `HttpConnPool` (`proto/httpclient.nim:85,166,187`), `100-continue` strip and replay. H2 trailers (`END_STREAM` + trailing `HEADERS`) depend on trailer support.

## 1. ALPN and TLS negotiation (RFC 7540 section 3.3, 9.2)

Files: `src/powpow/net/tlsapi.nim`, `src/powpow/net/tls.nim`, `src/powpow/proto/httpserver.nim`, `src/powpow/proto/httpclient.nim`.

- Bind `SSL_CTX_set_alpn_protos`, `SSL_set_alpn_protos`, `SSL_select_next_proto`, `SSL_get0_alpn_selected`, `SSL_CTX_set_alpn_select_cb`.
- Server: advertise `["h2","http/1.1"]`, select `h2` when offered. Expose `conn.alpnSelected()` returning `""` / `"h2"` / `"http/1.1"`.
- Client: send `["h2","http/1.1"]` for `https://`. Branch on selected proto after `driveHandshake` (`net/tcp.nim:329,1615,2340`).
- Tests: extend `tests/test_tls.nim` — server sees `h2`, client sees `h2`, fallback to `http/1.1` against H1-only peer.

## 2. Frame codec — `src/powpow/proto/http2.nim` (new, RFC 7540 section 4, 6)

- 9-byte header (24-bit length, 8-bit type, 8-bit flags, 31-bit stream id).
- Types: `DATA(0) HEADERS(1) PRIORITY(2) RST_STREAM(3) SETTINGS(4) PUSH(5, deferred, protocol error if received) PING(6) GOAWAY(7) WINDOW_UPDATE(8) CONTINUATION(9)`.
- Strict validation: max frame `SETTINGS_MAX_FRAME_SIZE` (16K to 16M), `SETTINGS` on stream 0 only, `CONTINUATION` sequencing, unknown type skip (section 5.5), connection error codes section 7 (`PROTOCOL_ERROR, FLOW_CONTROL_ERROR, FRAME_SIZE_ERROR, COMPRESSION_ERROR, ENHANCE_YOUR_CALM`).
- Incremental `feed(openArray[byte])` parser reusing H1 zero-copy style (`proto/http.nim:1029`). Single writer emitting `SETTINGS, HEADERS, DATA, PING, WINDOW_UPDATE, RST_STREAM, GOAWAY`.
- Unit tests: `tests/test_http2_frames.nim` — one test per frame type plus malformed, oversize, and unknown frame cases.

## 3. HPACK — `src/powpow/proto/hpack.nim` (new, RFC 7541 full)

- Static table (61 entries), dynamic table with `SETTINGS_HEADER_TABLE_SIZE` resizing and eviction, Huffman encode/decode with spec tables, indexed, literal, incremental indexing, never indexed, plus table size update.
- Decode errors surface as `COMPRESSION_ERROR` connection errors.
- Tests: `tests/test_hpack.nim` using RFC 7541 Appendix C vectors (must pass verbatim before integration).

## 4. Connection and stream state machine (RFC 7540 section 5)

New shared `H2Conn` used by both server and client (owns `Connection` + `Loop` fd).

- Preface (section 3.4, 3.5): server expects `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` + `SETTINGS`. Client sends it. h2c Upgrade path (section 3.2): H1 `Upgrade: h2c, HTTP2-Settings` yields `101 Switching` then preface. Prior knowledge skips Upgrade.
- `SETTINGS` negotiation (section 6.5): exchange plus ACK, apply `HEADER_TABLE_SIZE, ENABLE_PUSH(0, since deferred), MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE (up to 2^31-1), MAX_FRAME_SIZE, MAX_HEADER_LIST_SIZE`.
- Stream states (section 5.1): `idle -> open -> halfClosed(remote/local) -> closed`, plus `reserved` stub returning `PROTOCOL_ERROR` for PUSH. Odd/even id discipline (client odd, server even/push even deferred), `GOAWAY` last-stream-id plus graceful drain.
- Flow control (section 6.9): connection and per-stream windows (init 64K-1), `WINDOW_UPDATE` emission on consume, send blocking when window exhausted, `FLOW_CONTROL_ERROR` on overflow.
- Multiplexing: `StreamId -> H2Stream` table. Inbound `HEADERS` dispatches to handler, `DATA` goes to body buffer or file stream (reuse tempfile streaming threshold from `httpserver.nim:1075` for large bodies, critical since streams share one TCP connection per `plans/pre-http2.md:55`).

## 5. HTTP mapping (RFC 7540 section 8)

- `HEADERS` maps to `HttpRequest`/`HttpResponse`: `:method :path :scheme :authority` maps to existing `getMethod/getPath/getUrl/materializeHeaders` (`proto/http.nim:1274ff`). Pseudo-header validation (presence, order, no `Connection/Upgrade/Transfer-Encoding` except h2c upgrade request itself).
- Server: dispatch to existing `handler(req,res)` in `httpserver.nim:995,1009` so H1 and H2 share app code. Response path emits `HEADERS` + `DATA` (plus trailing `HEADERS` if trailers present) instead of `HTTP/1.1` status line.
- Client: map `requestImpl/buildRequestHeaders` (`httpclient.nim:247,298,561`) to `HEADERS`. Multiplex concurrent `async` requests on one `H2Conn` (lifts current 1-in-flight cap `httpclient.nim:718`). Keep `HttpConnPool` keyed by origin but pool `H2Conn` (with `maxConcurrentStreams` cap), retain transparent retry (`retryFresh:366`) mapped to `RST_STREAM`/`GOAWAY` retries.
- `Content-Length` end-to-end (no chunked on H2). `DATA` `END_STREAM` flag delimits body.

## 6. I/O integration — epoll default, io_uring guarded

- No new backend. H2 reads and writes go through existing `Connection.send/sendv/flushWriteBuffer` (`net/tcp.nim:1234,1276,1225`) so both readiness (epoll/kqueue) and submission (`io/uring.nim` `RECV/SEND/SEND_ZC/SPLICE`) paths work unchanged.
- TLS over io_uring stays on mem-BIO path. Large `DATA` reuses `continueSendFile` SPLICE/`READ+SEND` pump (`net/tcp.nim:1182,2809`), with fallback to `read+send` when `isTlsActive` (same rule as `httpserver.nim:571,720`).
- Concurrency and backpressure: per-stream write queues drained by connection window. `sweepTimeouts` idle/read-timeout model (`httpserver.nim:959,985`) extended to `H2Conn.lastActive`. No per-stream timers in milestone 1.

## 7. Security, limits, interop (RFC 7540 section 9, 10)

- Enforce `MAX_CONCURRENT_STREAMS`, `MAX_HEADER_LIST_SIZE`, `MAX_FRAME_SIZE`, `INITIAL_WINDOW_SIZE` bounds. `RST_STREAM` on per-stream errors, `GOAWAY(ENHANCE_YOUR_CALM)` on flood. Reject `HTTP/2.0` on H1 port with existing `505` (`proto/http.nim:442`) preserved.
- h2c Upgrade must validate `HTTP2-Settings` base64url `SETTINGS` payload. Prior knowledge only on explicit opt-in (no accidental H1 misparse).
- Interop targets: `curl --http2`, `nghttpd/nghttp`, Go `x/net/http2` client against powpow H2 server and vice versa. Document cipher blacklist expectations (section 9.2.2) vs OpenSSL defaults.

## 8. Tests, docs, rollout

- New: `test_hpack.nim` (RFC vectors), `test_http2_frames.nim` (codec), `test_http2.nim` (server+client loopback: get, post, large body, multiplexed, concurrent, limit cases), `test_http2_security.nim` (oversize headers, window overflow, bad preface, CONTINUATION abuse, invalid pseudo-headers) mirroring `test_httpclient_security.nim` style.
- Existing suites unchanged and green: `test_http, test_security, test_bad_requests` (keep asserting `HTTP/2.0 -> 505/400` on H1 path), `test_io_uring` (guarded, Linux only).
- Docs: update `docs/overview.md`, `docs/performance.md`, `README` H2 status from Planned to Experimental. Add `docs/http2.md` (negotiation matrix, limits and knobs, io_uring notes).
- Milestones: M1 ALPN+codec+HPACK unit (no wire interop) -> M2 h2c server loopback -> M3 h2 TLS server -> M4 H2 client plus pool multiplexing -> M5 hardening, interop, docs. Land as stacked PRs off `feature/http2`, squash merge to `main` only when all suites green.

## Open risks

- ALPN binding surface in `tlsapi.nim` is the critical unknown. If OpenSSL version varies, pin minimum and feature detect.
- Flow control deadlocks under single-connection multiplexing are the main correctness risk. M4 needs deterministic window exhaustion tests.
- `ENABLE_PUSH=0` plus ignore inbound `PUSH_PROMISE` as `PROTOCOL_ERROR` keeps M1 honest while deferring push per scope decision.
