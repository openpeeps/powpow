---
title: Static files
description: "Serving files with powpow: sendFile, streamFile, serveFile and serveStatic, plus Range and conditional requests."
keywords: ["powpow", "static", "files", "sendfile", "range", "http"]
---

# Static files

powpow serves files with three APIs, each a different trade-off. They share the
same zero-copy core (`sendfile`) and the same safety checks (path-traversal and
symlink-escape protection).

Runnable example: [`examples/static_server.nim`](../../examples/static_server.nim)
and [`examples/stream_server.nim`](../../examples/stream_server.nim).

## API matrix

| API | Semantics | Use for |
|---|---|---|
| `res.sendFile(path, req, ...)` | One-shot zero-copy download; `Content-Disposition: attachment`; optional Range; closes the connection after (default) | downloads |
| `res.streamFile(path, req, chunkSize)` | Chunked streaming with keep-alive and Range awareness; 1 MiB default chunks | media streaming |
| `serveFile(res, req, path, fsRoot, ...)` | Full conditional request handling: `If-None-Match`, `If-Modified-Since`, `If-Range`, Range, `304`/`206` | resumable downloads |
| `serveStatic(res, req, urlPrefix, fsRoot, indexFiles)` | Serve a whole directory tree from a root, with index files and MIME detection | static sites |

`serveFile`/`serveStatic` return `bool` — `false` means the file was not found
under the root (caller sends its own 404).

## Examples

```nim
# A /download route — attachment, Range-aware
res.sendFile("/var/data/report.pdf", req)

# A /video route — streamed, keep-alive, Range-aware
res.streamFile("/var/media/big.webm", req)

# A /resume route — full conditional + Range handling
discard serveFile(res, req, "/var/media/big.webm",
                  fsRoot = "/var/media")

# A static site at /static/* served from ./www
discard serveStatic(res, req, "/static", "./www",
                    indexFiles = ["index.html", "index.htm"])
```

## Range & conditional requests

`parseRange(rangeHeader: string; fileSize: int64): (ok, start, length)` is the
RFC 7233 parser used internally:

```nim
let (ok, start, length) = parseRange(req.getHeaders()["Range"][0], fileSize)
```

`serveFile` handles `If-None-Match` (ETag derived from size + mtime),
`If-Modified-Since`, `If-Range` and `Range`, emitting `304 Not Modified` and
`206 Partial Content` as appropriate. `streamFile` is always Range-aware.

## MIME types & helpers

- `getFileExt(path): string` — extension from a path
- MIME detection is based on file extensions via the `mimedb` package

## Safety

All serving goes through `resolveReal(path)` (realpath) and
`withinRoot(root, path)`, so:

- A sibling directory sharing the root's prefix cannot be served
  (e.g. `/var/www2` under root `/var/www` → rejected).
- A symlink inside the root that points outside → `403`.
- Path traversal (`../`) → rejected.

`skipRange` and `attach` options disable the features you don't need.
`serveFile`'s `contentType`, `etag`, `lastModified` and `chunkSize` parameters
override the defaults.

## API reference

Full signatures: [HTTP server API](../api/httpserver.md). Related:
[server](server.md).
