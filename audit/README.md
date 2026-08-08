# Security regression harness

This directory contains standalone, runnable regression tests for the findings
of the security audit. Each file is self-contained and **red on the pre-fix
code, green after the fix**, so it can be run periodically to catch
regressions. The tests cover both powpow and the sibling `multipart` checkout
it depends on.

## Run everything

```sh
cd /Users/georgelemon/Development/packages/powpow
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
