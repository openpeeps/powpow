Security Audit Plan — powpow

> **STATUS (2026-08-08): audit executed.** Phase 0 items 1–7 and the Phase-6
> rate-limiter item are confirmed FIXED (regression tests in
> `tests/test_security.nim`, `audit/`, and `multipart/tests/test_security.nim`).
> The audit additionally found and fixed: a remote-crash `IndexDefect` in the
> multipart dependency (malformed part headers and bodies without a leading
> boundary), chunked-streaming bodies never completing, chunked uploads
> uncapped when `maxBodySize==0`, `serveStatic` sibling-prefix leak + broken
> documented prefix, an unbounded per-connection write buffer (slow-read DoS),
> and world-readable/symlink-following temp upload files. Full findings,
> repros and fixes: **`audit/REPORT.md`**. Open follow-ups (not fixed):
> Windows symlink canonicalization for static serving, post-upgrade WS idle
> timeout, `parseRange` leniency, UDP empty-send, and operator-set size caps.
>
> Original plan (for reference):

Objectives
1. Confirm or refute the findings below with reproducible PoCs/tests.
2. Find issues the inventory missed (fuzzing, edge cases).
3. Produce a prioritized, actionable fix list with regression tests.
Threat model
- Attacker: unauthenticated remote client sending arbitrary bytes to HTTP/WS/TCP/UDP endpoints (and unauthenticated file uploads for static/multipart paths).
- Trust boundaries: socket input → parsers → app callbacks; filesystem (static serving, temp-file streaming).
- Impact classes: memory unsafety, request smuggling/desync, RCE, DoS (memory/CPU/disk/connection), path traversal.
Scope
In-scope: proto/http.nim, proto/ws.nim, proto/httpserver.nim, proto/simdscan.nim, proto/ratelimit.nim, net/tcp.nim, net/udp.nim, net/common.nim, platform/* (iocp/poll focus), and the multipart dependency at ~/Development/packages/multipart.
Out-of-scope: TLS internals (OpenSSL), multithread scheduler correctness (covered only for rate-limiter races).
Phase 0 — Hypothesis verification (highest-value findings to confirm first)
Each item gets a PoC test before any fix:
1. Content-Length overflow off-by-one — http.nim:391-396: num > high(int) div 10 allows 9223372036854775808 to wrap negative. Verify in -d:release (→ negative contentLength, desync primitive) and debug (→ RangeDefect crash). Compare with the safe parseChunkSize check.
2. Dead timeouts — readTimeoutMs/keepAliveMs never registered as timers. Confirm no timer is armed, then measure slowloris resource cost (grow 1000 idle conns, check RAM/fd usage).
3. serveFile prefix confusion — httpserver.nim:975 startsWith(fsRoot) serves /var/www2. Reproduce with fsRoot=/var/www and sibling dir.
4. sendFile stack overflow — httpserver.nim:402 hdrBuf array[768] + writeDisposition with a long filename. Build with ASAN and serve a >700-byte filename.
5. WS unbounded alloc when maxFrameSize==0 — ws.nim:398-400,428-430,455-457: int(payloadLen)→newSeq unbounded; 64-bit wrap → negative index in dispatch.
6. Allocation before limits — http.nim:525-528,752 grows buffer before MaxHeaderSize/MaxRequestLine checks; default maxBodySize=0 buffers whole body. Measure single-packet 100 MB POST → RSS.
7. Disk fill — auto-stream-to-tempfile (httpserver.nim:800-809) and multipart file writes unbounded when no size limit. Confirm no cap in default config.
Phase 1 — Fuzzing & sanitizers
- Fuzz harness (new, under tests/fuzz/): deterministic mutational harness feeding the HTTP parser (feed), WS parser (parseWsFrames), and multipart streamer with random byte sequences (structured seeds: \r\n\r\n, chunked headers, frame headers, boundaries). Run N=1M iterations locally; bounded (e.g. 50k) in CI.
- ASAN/UBSAN builds: nim c --passC:"-fsanitize=address,undefined" --passL:"-fsanitize=address,undefined". Run the full test suite + fuzz harness under sanitizers.
- Overflow-checks matrix: run parser suites with --overflowChecks:on --boundChecks:on AND release (--overflowChecks:off) to expose both defect and wraparound paths.
- SIMD scanner: targeted fuzz of findCRLF/findDoubleCRLF on lengths 1–64 crossing the 16-byte SSE2 boundary (existing test_sse2* + new adversarial lengths).
Phase 2 — Protocol-level review (manual + crafted cases)
- Request smuggling: CL+TE precedence, duplicate-CL-different (covered by tests), trailing-garbage CL (Content-Length: 5x), Transfer-Encoding non-"chunked" token enabling chunked mode (http.nim:428-429), chunked trailer handling.
- WS framing: fragmentation/continuation state machine, control-frame interleave, close-code whitelist, masked-frame handling (already added), 64-bit length edge values.
- HTTP pipelining / streaming phase confusion: negative contentLength path through feed and resetForNext; consumed-byte arithmetic under partial feeds.
Phase 3 — DoS / resource-exhaustion
- Memory: buffer-growth-before-limit, getBody second allocation, WS payload, response reflection via TLS sendv coalescing (tcp.nim:314-321).
- Connections: prove the missing idle/keep-alive/read timeout; recommend implementing via the existing timer wheel; add maxHeaderBytes-bounded read windowing.
- Disk: temp-file streaming caps; multipart sizeLimit/per-file caps wired through httpserver.nim:794-799; ensure MultipartSizeLimitError is caught → 413 instead of unhandled exception in the loop callback.
- CPU: findDoubleCRLF uncapped scan (minor); slowloris header/body (needs the timeout from above).
Phase 4 — Static file serving & filesystem
- Path traversal: .., ~, leading /, %2e%2e, symlink escape (realpath check), null-byte in path.
- Verify all serveFile/sendFile/streamFile/serveStatic paths; confirm the 768-byte header-buffer bounds across sendFile, streamFile, range responses.
- Temp-file lifecycle: cleanup on error/close, OID collisions, permissions (getTempDir() world-readable).
Phase 5 — Dependency review: ~/Development/packages/multipart (multipart.nim, 1251 lines)
- Verify the local checkout is the version powpow actually builds against (vendored 0.1.2 is byte-identical today; confirm nimble resolution won't drift).
- Review: parseHeader/unescape for memory safety, writeDataByte temp-file handling, maxFieldSize/maxField enforcement (local HEAD commit 48655f7 mentions a fix — verify it's in the installed copy), boundary/boundary-count limits, size-limit defaults (0 = unlimited), exception → 413 path.
- Fuzz the streamer and buffered parser with malformed boundaries/header lines.
Phase 6 — Concurrency & misc
- Rate limiter (ratelimit.nim:60-71): Table not thread-safe — race in MultiThreadHttpServer with a shared limiter.
- HTTP header count/size, method length, version parsing bounds re-check.
- closeWs reason-length footgun; writeFrameMasked full-copy allocation.
Deliverables
1. Audit report — each finding: file:line, severity, exploitability, repro test, recommended fix.
2. Regression tests in tests/test_security.nim (and a new tests/test_security2.nim if needed) covering all confirmed issues.
3. Fuzz harness + CI job (bounded) + sanitizer build instructions.
4. Fix recommendations prioritized (P0/P1/P2), with the timeout enforcement and size-limit wiring as the top infrastructure changes.
Suggested sequencing (once you approve)
A. Phase 0 items 1–4 (quick PoCs, highest signal) → B. Phases 1–2 (fuzzing + protocol) → C. Phase 3 (DoS/infrastructure fixes) → D. Phases 4–6 → E. report.
