---
title: Streaming and range downloads
description: "streamFile, sendFile and serveFile compared on one big video file."
keywords: ["powpow", "example", "stream_server"]
---

# Streaming and range downloads

Three ways to ship a large file, each with different semantics. The example expects `Big_Buck_Bunny_4K.webm` (about 2.76 GB) next to it, but any file works.

Source: [`examples/stream_server.nim`](../../examples/stream_server.nim)

```nim
import ../src/powpow
import std/httpcore

# We are going to use Big_buck_Bunny_4K.webm as a test file for streaming and downloading.
# You can download this ~2.76 GB file from Wikipedia: https://en.wikipedia.org/wiki/File:Big_Buck_Bunny_4K.webm

let server = newHttpServer()

proc handler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  let path = req.getPath()

  if path == "/video":
    # streamFile: media streaming with chunk limiting (1 MB per response),
    # always keep-alive, always handles Range requests
    res.streamFile("./Big_Buck_Bunny_4K.webm", req)

  elif path == "/download":
    # sendFile: file download with Content-Disposition: attachment,
    # optional Range support, configurable connection close
    res.sendFile("./Big_Buck_Bunny_4K.webm", req, closeConn = false)

  elif path == "/resume":
    # serveFile: high-level file serving with resume download support.
    # Handles If-None-Match, If-Modified-Since, If-Range, and Range
    # automatically. ETag is computed from file size + mtime.
    # Returns 304 for unchanged files, 206 for partial content.
    discard res.serveFile(req, "./Big_Buck_Bunny_4K.webm", attach = true)

  else:
    res.sendError(Http404, "Not Found")

echo "💥 powpow HTTP server listening on http://localhost:9002"
echo "  Press Ctrl+C to stop"
server.start(handler, Port(9002))
```

## Running

```bash
nim c -r examples/stream_server.nim
```

## Try it

```bash
curl -r 0-1023 -i http://localhost:9002/video   # first KB via Range
curl -OJ http://localhost:9002/download            # attachment download
curl -i http://localhost:9002/resume               # ETag/304 handling
```

## How it works

- `res.streamFile(path, req)`: media streaming with chunk limiting (1 MB per write), keep-alive friendly, automatic Range handling.
- `res.sendFile(path, req, closeConn = false)`: download semantics with `Content-Disposition: attachment`, optional Range support and explicit connection-close control.
- `discard res.serveFile(req, path, attach = true)`: the high-level variant that also honors `If-None-Match`, `If-Modified-Since` and `If-Range`; ETags derive from size + mtime, yielding 304 for unchanged and 206 for partial requests.
- All three never load the file into memory; bytes flow straight from disk to the socket.

See the [static files guide](../http/static-files.md) and [API reference](../api/httpserver.md).

