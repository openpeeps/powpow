import ../src/powpow
import std/[httpcore, os]

let loop = newLoop()
let server = newHttpServer(loop)

# streamFile: media streaming with chunk limiting (1 MB per response),
# always keep-alive, always handles Range requests
server.get("/video") do (req: HttpRequest, res: Response):
  res.streamFile("./Big_Buck_Bunny_4K.webm", req)

# sendFile: file download with Content-Disposition: attachment,
# optional Range support, configurable connection close
server.get("/download") do (req: HttpRequest, res: Response):
  res.sendFile("./Big_Buck_Bunny_4K.webm", req, closeConn = false)

server.listen("127.0.0.1", 9002)
loop.run()
server.close()
loop.close()