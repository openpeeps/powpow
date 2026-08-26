---
title: File uploads
description: "Raw-body uploads via streamToFile and multipart via getMultipart."
keywords: ["powpow", "example", "upload_server"]
---

# File uploads

Two upload styles on one server. `/upload/raw` persists the raw request body to a temp file with `streamToFile` (best for trusted server-to-server transfers where metadata travels out-of-band). `/upload/stream` parses `multipart/form-data` incrementally with `getMultipart`, exposing fields and files as they complete.

Source: [`examples/upload_server.nim`](../../examples/upload_server.nim)

```nim
## examples/upload_server.nim — File upload demo using zero-copy APIs.
##
## Demonstrates two upload approaches:
##
##   /upload/raw     — Raw body via streamToFile() (recommended for trusted
##                     server-to-server transfers; the body carries no metadata,
##                     so the filename/type must be conveyed out-of-band)
##   /upload/stream  — Multipart via getMultipart() (fields + files)
##
## Run:
##   nim c -r examples/upload_server.nim
##
## Test:
##   curl -X POST http://localhost:9000/upload/raw --data-binary @bigfile.bin
##   curl -X POST http://localhost:9000/upload/stream -F "file=@bigfile.bin"

import ../src/powpow
import std/[httpcore, strutils]

let server = newHttpServer()

# ── Handler ──────────────────────────────────────────────────────────────────

proc handler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  {.gcsafe.}:
    let meth = req.getMethod()
    let path = req.getPath()

    if meth == HttpPost:
      case path
      of "/upload/raw":
        let path = req.streamToFile()
        let fileSize = getFileSize(openFileRead(path))
        res.status(Http200)
          .header("Content-Type", "application/json")
          .send("{\"filePath\": \"" & path & "\", \"fileSize\": " & $fileSize & "}")

      of "/upload/stream":
        let mp = req.getMultipart()
        if mp == nil or not mp.isComplete():
          res.sendError(Http400, "Expected multipart/form-data")
          return

        var results: seq[string]
        for b in mp:
          case b.dataType
          of MultipartFile:
            results.add("{\"type\": \"file\", \"fieldName\": \"" & b.fieldName &
                        "\", \"fileName\": \"" & b.fileName &
                        "\", \"fileType\": \"" & b.fileType &
                        "\", \"fileSize\": " & $b.fileSize &
                        ", \"filePath\": \"" & b.filePath & "\"}")
          of MultipartText:
            results.add("{\"type\": \"text\", \"fieldName\": \"" & b.fieldName &
                        "\", \"value\": \"" & b.value & "\"}")

        mp.cleanup()

        res.status(Http200)
          .header("Content-Type", "application/json")
          .send("[" & results.join(", ") & "]")

      else:
        res.sendError(Http404,
          "404 Not Found: " & $meth & " " & path)

    else:
      res.sendError(Http404,
        "404 Not Found: " & $meth & " " & path)

# ── Start ────────────────────────────────────────────────────────────────────

echo "Upload server listening on http://localhost:9000"
echo "  POST /upload/raw   — raw body via streamToFile() (trusted server-to-server transfers)"
echo "  POST /upload/stream — multipart via getMultipart()"
echo "  Press Ctrl+C to stop"
server.start(handler, Port(9000))
```

## Running

```bash
nim c -r examples/upload_server.nim
```

## Try it

```bash
curl -X POST http://localhost:9000/upload/raw --data-binary @bigfile.bin
curl -X POST http://localhost:9000/upload/stream -F "file=@bigfile.bin" -F "note=hello"
```

## How it works

- `req.streamToFile()` streams the body to disk without buffering it whole and returns the written path.
- `req.getMultipart()` returns nil unless the content type is multipart; check `isComplete()` before iterating.
- Iterating the multipart object yields parts tagged `MultipartFile` (with `fieldName`, `fileName`, `fileType`, `fileSize`, spooled `filePath`) or `MultipartText` (with `value`).
- `mp.cleanup()` removes the temporary files created during parsing.

Deep dive in the [multipart guide](../http/multipart.md).

