---
title: Multipart & uploads
description: "Bounded-memory file uploads with powpow: streamToFile for raw bodies and getMultipart for multipart forms."
keywords: ["powpow", "multipart", "upload", "file", "streaming"]
---

# Multipart & uploads

powpow handles file uploads with bounded memory: multipart bodies are parsed on
the fly (`getMultipart`) or streamed straight to disk (`streamToFile`).

Runnable example: [`examples/upload_server.nim`](../../examples/upload_server.nim).

## Raw body → disk

```nim
proc handler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  if req.getPath() == "/upload/raw":
    let tmpPath = req.streamToFile(tmpDir = "/tmp")
    res.send("stored as " & tmpPath)
```

`streamToFile(tmpDir = "")` streams the **raw request body** to a temp file,
returning the file path. Memory stays flat regardless of body size. The body
carries no metadata, so filename/type must be conveyed out-of-band — this is the
recommended path for trusted server-to-server transfers.

## Multipart parsing

```nim
proc handler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  if req.getPath() == "/upload/stream":
    let mp = req.getMultipart(tmpDir = "/tmp")   # MultipartStreamerRef
    # mp exposes MultipartFile / MultipartText parts — iterate and consume
    res.send("multipart processed")
```

`getMultipart(tmpDir = "")` parses `multipart/form-data` incrementally as the
body streams in, exposing fields and files. Multipart is handled by the
[`multipart`](https://github.com/...) package (dependency `multipart >= 0.1.4`),
integrated with powpow's streaming body.

## Limits

Per-file and per-field caps are wired into server config and enforced by the
parser:

| Field | Cap |
|---|---|
| `server.maxFileSize` | single uploaded file part (default 10 MB in the recommended config) |
| `server.maxFieldSize` | single text field |
| `server.maxBodySize` | total request body |

Violations reply `413` instead of raising — see [security](../security.md).

## API reference

Full signatures: [HTTP parser API](../api/http.md). Related:
[requests](requests.md), [security](../security.md).
