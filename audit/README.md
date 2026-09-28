# Security regression harness

This directory contains standalone, runnable regression tests for the findings
of the security audit. Each file is self-contained and **red on the pre-fix
code, green after the fix**, so it can be run periodically to catch
regressions. The tests cover both powpow and the sibling `multipart` checkout
it depends on.

## Run everything

```sh
for f in audit/*.nim; do
  nim c -r --hints:off --verbosity:0 "$f" || echo "FAILED: $f"
done
```

Individual audits run the same way, e.g. `nim c -r audit/powpow_multipart_server.nim`.

> Note: filenames must be valid Nim identifiers (no leading digits) so they can
> be compiled directly.

`audit/config.nims` puts the local powpow `src/` on the module path and prepends
the sibling `multipart/src` checkout so the multipart audits exercise the source
we actually patch (not a stale nimble-installed copy).

## Index

| File | Finding | Pre-fix symptom |
|---|---|---|
| `multipart_parser_crash.nim` | P0 — IndexDefect crash on malformed part headers (`parseHeader`/`createPart`) | process aborts with `IndexDefect` |
| `multipart_buffered_crash.nim` | P2 — buffered `parse()` crashes on body without leading boundary (`mp.boundaries[^1]`) | `IndexDefect: index out of bounds` |
| `powpow_multipart_server.nim` | P0 — malformed multipart aborts the HTTP server through the event loop | unhandled `IndexDefect`, no response |
| `chunked_streaming.nim` | P1 — chunked streaming bodies never complete / raw framing forwarded | stays `PhaseBody`, `done` never fires |
| `tempfile_permissions.nim` | P2 — uploaded temp files world-readable (0644) + symlink-following open | `fpOthersRead` set |
| `serve_static.nim` | P1 — `serveStatic` broken prefix handling: `/staticx` leaked, `/static` 403 | `/staticx/file` → 200, `/static/file` → 403 |
| `timer_cancel_regression.nim` | regression pin — cancelled timers never fire | (guards a confirmed false positive) |
| `ws_idle_timeout.nim` | R2 — post-upgrade WS idle/read timeout | silent upgraded conn never closes |
| `parse_range.nim` | R2 — `parseRange` trailing-garbage / multi-range strictness | `bytes=0-5x` silently truncated |
| `udp_empty_send.nim` | R2 — UDP empty payload `unsafeAddr data[0]` | OOB read on empty send |
| `request_line_strict.nim` | R2 — strict request line + SSE2 `\r\n` boundary bug | pipelined requests misparse (400) |
| `size_backstop.nim` | R2 — configurable `maxStreamBodySize` hard cap | 512 MB backstop not tunable |
| `h2_hpack_hostile.nim` | H2 pin — HPACK hostile ints/strings/indexes all raise `HpackError` | (all green; guards `decodeInt`/`decodeString`/`lookupIndex`) |
| `h2_hpack_bad_huffman.nim` | H2 pin — Huffman EOS/invalid-code/bad-padding all raise | (all green; ones-padding acceptance pinned as RFC-mandated) |
| `h2_hpack_table_accounting.nim` | H2 pin — dynamic-table eviction/index/size-update exact | (all green; mid-block size update pinned as accepted leniency) |
| `h2_continuation_bomb.nim` | H2 P1 — unbounded `fragBuf` across CONTINUATIONs (fixed: incremental cap, COMPRESSION_ERROR) | RSS +35 MB for 8 MB of fragments |
| `h2_stream_machine.nim` | H2 pin — idle/closed DATA/RST/WU, trailers, post-GOAWAY refusal | (all green) |
| `h2_flood_policy.nim` | H2 finding — no generic rate limiter (bounded 1:1 per vector; limits proposed) | PING/SETTINGS/RST/open-RST floods measured, no superlinear cost |
| `h2_upgrade_strict.nim` | H2 pin — h2c upgrade validation (bad b64, hostile settings, CL, sniff cap, TE fail-closed) | (all green) |
| `h2_flow_control.nim` | H2 pin — window accounting under burst, IWS=0 stall/release | (all green; conn-level backstop unreachable by design) |
| `h2_frame_size.nim` | H2 pin — fixed-length violations, split/incomplete reassembly, padding, extensions | (all green) |
| `h2_goaway_drain.nim` | H2 pin — lastStreamId accuracy, in-flight counting, post-teardown silence | (all green) |
