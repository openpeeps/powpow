## examples/upload_server.nim — File upload demo using zero-copy APIs.
##
## Demonstrates three approaches:
##
##   /upload/raw     — Raw body via streamToFile()  (~68KB — recommended)
##   /upload/stream  — Multipart via getMultipart()  (~68KB, same as /lazy)
##
## The two multipart routes (/lazy, /stream) are identical — both use
## auto-detected streaming.
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
echo "  POST /upload/raw   — raw body via streamToFile() (~68KB — recommended)"
echo "  POST /upload/stream — multipart via getMultipart() (~68KB, same as /lazy)"
echo "  Press Ctrl+C to stop"
server.start(handler, Port(9000))
