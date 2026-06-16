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

  else:
    res.sendError(Http404, "Not Found")

server.start(handler, Port(9002))
