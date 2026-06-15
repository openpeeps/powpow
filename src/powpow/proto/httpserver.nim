## powpow/proto/httpserver.nim — Non-blocking HTTP/1.1 server.
##
## Combines the TCP transport layer with the incremental HTTP parser
## to provide a high-level routing server with minimal overhead.
##
## Usage:
##   let server = newHttpServer(loop)
##   server.get("/") do (req: HttpRequest, res: Response):
##     res.status(Http200).send("Hello!")
##   server.listen("0.0.0.0", 8080)
##   loop.run()

import ../net/tcp
import ../loop
import ../types
import http
import std/[httpcore, tables, strutils, times, posix]

# ── Types ────────────────────────────────────────────────────────────────────

type
  Response* {.acyclic.} = ref object
    ## Build and send an HTTP response.
    conn:       Connection
    sent:       bool
    statusCode: HttpCode
    headers:    seq[(string, string)]
    bodyBytes:  seq[byte]
    closeConn:  bool           ## If true, send "Connection: close" and shut down

  Handler* = proc(req: HttpRequest, res: Response) {.closure.}
    ## Route handler. Call `res.status(...).send(...)` to respond.

  # RouteKey = object
  #   httpMethod: HttpMethod
  #   path:   string

  Session = object
    ## Per-connection state.
    parser: HttpParser
    idleTimer: TimerId
    idleMs:    int

  HttpServer* {.acyclic.} = ref object
    ## A non-blocking HTTP/1.1 server.
    tcpServer: TcpServer
    loop:      Loop
    routes:    Table[string, Handler]      ## "METHOD /path" → handler
    fallback:  Handler                      ## Catch-all handler (nil = 404)
    sessions:  Table[int, Session]          ## fd → parser session
    keepAliveMs: int

const DefaultKeepAliveMs* = 5_000 

# ── Response ─────────────────────────────────────────────────────────────────

proc newResponse(conn: Connection): Response =
  Response(
    conn:       conn,
    sent:       false,
    statusCode: Http200,
    headers:    @[],
    bodyBytes:  @[],
    closeConn:  false,
  )

proc status*(res: Response, code: HttpCode): Response {.discardable.} =
  ## Set the HTTP status code.
  res.statusCode = code
  return res

proc header*(res: Response, key, value: string): Response {.discardable.} =
  ## Add a response header.
  res.headers.add((key, value))
  return res

proc close*(res: Response): Response {.discardable.} =
  ## Mark this response to send "Connection: close" and shut down the
  ## TCP connection after the response is sent.
  res.closeConn = true
  return res

proc send*(res: Response, body: string = "") =
  ## Send the response with a string body.
  if res.sent: return
  res.sent = true
  let connHeader = if res.closeConn: "close" else: "keep-alive"
  if body.len > 0:
    var resp = "HTTP/1.1 " & $res.statusCode.int & " " & $res.statusCode & "\r\n"
    resp.add("Content-Length: ")
    resp.add($body.len)
    resp.add("\r\nConnection: ")
    resp.add(connHeader)
    resp.add("\r\nServer: powpow/0.1.0\r\n")
    for (k, v) in res.headers:
      resp.add(k); resp.add(": "); resp.add(v); resp.add("\r\n")
    resp.add("\r\n")
    resp.add(body)
    discard res.conn.send(resp)
  else:
    var resp = "HTTP/1.1 " & $res.statusCode.int & " " & $res.statusCode & "\r\n"
    resp.add("Content-Length: 0\r\nConnection: ")
    resp.add(connHeader)
    resp.add("\r\nServer: powpow/0.1.0\r\n")
    for (k, v) in res.headers:
      resp.add(k); resp.add(": "); resp.add(v); resp.add("\r\n")
    resp.add("\r\n")
    discard res.conn.send(resp)
  if res.closeConn:
    res.conn.shutdown()

proc send*(res: Response, body: seq[byte]) =
  ## Send the response with a raw byte body.
  if res.sent: return
  res.sent = true
  let connHeader = if res.closeConn: "close" else: "keep-alive"
  var resp = "HTTP/1.1 " & $res.statusCode.int & " " & $res.statusCode & "\r\n"
  resp.add("Content-Length: ")
  resp.add($body.len)
  resp.add("\r\nConnection: ")
  resp.add(connHeader)
  resp.add("\r\nServer: powpow/0.1.0\r\n")
  for (k, v) in res.headers:
    resp.add(k); resp.add(": "); resp.add(v); resp.add("\r\n")
  resp.add("\r\n")
  discard res.conn.send(resp)
  if body.len > 0:
    discard res.conn.send(body)
  if res.closeConn:
    res.conn.shutdown()

proc sendError*(res: Response, code: HttpCode, msg: string = "") =
  ## Send an error response and close the connection.
  res.status(code)
  res.header("Content-Type", "text/plain; charset=utf-8")
  res.close()
  res.send(msg)

proc getConn*(res: Response): Connection {.inline.} =
  ## Get the underlying TCP connection. Used by protocol upgrade
  ## handlers (e.g. WebSocket) that need direct access to the socket.
  res.conn

proc markSent*(res: Response) {.inline.} =
  ## Mark this response as sent without writing any bytes.
  ## Used by upgrade handlers that send the response manually.
  res.sent = true

# ── Route key helper ─────────────────────────────────────────────────────────

proc routeKey(m: HttpMethod, path: string): string {.inline.} =
  $m & " " & path

# ── HttpServer lifecycle ─────────────────────────────────────────────────────

proc newHttpServer*(loop: Loop): HttpServer =
  ## Create a new HTTP server.
  HttpServer(
    tcpServer: nil,
    loop:      loop,
    routes:    initTable[string, Handler](64),
    fallback:  nil,
    sessions:  initTable[int, Session](64),
    keepAliveMs: DefaultKeepAliveMs
  )

proc setKeepAliveTimeout*(server: HttpServer, ms: int) =
  ## Set the keep-alive idle timeout in milliseconds. 0 disables it.
  server.keepAliveMs = ms

proc removeSession*(server: HttpServer, fd: int) =
  ## Clean up a connection's session. Public so protocol upgrade
  ## handlers (e.g. WebSocket) can take over a connection.
  server.sessions.del(fd)

# ── Request dispatch ─────────────────────────────────────────────────────────

proc dispatchRequest(server: HttpServer, conn: Connection,
                     req: HttpRequest) =
  ## Find a matching route and invoke the handler.
  let key = routeKey(req.getMethod(), req.getPath())
  let res = newResponse(conn)

  # Respect client's "Connection: close" header
  let reqHeaders = req.getHeaders()
  if reqHeaders.hasKey("Connection"):
    let connVal = reqHeaders["Connection"]
    if connVal.len > 0 and connVal == "close":
      res.closeConn = true

  if key in server.routes:
    server.routes[key](req, res)
  elif server.fallback != nil:
    server.fallback(req, res)
  else:
    res.sendError(Http404, "Not Found")


proc handleConnectionData(server: HttpServer, conn: Connection,
                          data: openArray[byte]) =
  ## Feed incoming bytes into the per-connection parser.
  let fd = conn.fd.int
  if fd notin server.sessions:
    server.sessions[fd] = Session(parser: newHttpParser())

  let phase = server.sessions[fd].parser.feed(data)

  if server.sessions[fd].parser.isComplete():
    let req = server.sessions[fd].parser.getRequest()
    server.dispatchRequest(conn, req)
    # The session may have been removed by a protocol upgrade handler
    # (e.g. websocketUpgrade). Re-check before touching the parser.
    if fd in server.sessions:
      server.sessions[fd].parser.reset()
  elif server.sessions[fd].parser.isError():
    let errCode = server.sessions[fd].parser.error()
    let res = newResponse(conn)
    res.sendError(errCode, "Bad Request")
    if fd in server.sessions:
      server.sessions[fd].parser.reset()
    # Don't close — let the client decide

# ── Route registration ───────────────────────────────────────────────────────

proc route*(server: HttpServer, meth: HttpMethod, path: string,
            handler: Handler) =
  ## Register a route handler.
  server.routes[routeKey(meth, path)] = handler

proc get*(server: HttpServer, path: string, handler: Handler) =
  ## Register a GET route handler.
  server.route(HttpGet, path, handler)

proc post*(server: HttpServer, path: string, handler: Handler) =
  ## Register a POST route handler.
  server.route(HttpPost, path, handler)

proc put*(server: HttpServer, path: string, handler: Handler) =
  ## Register a PUT route handler.
  server.route(HttpPut, path, handler)

proc patch*(server: HttpServer, path: string, handler: Handler) =
  ## Register a PATCH route handler.
  server.route(HttpPatch, path, handler)

proc delete*(server: HttpServer, path: string, handler: Handler) =
  ## Register a DELETE route handler.
  server.route(HttpDelete, path, handler)

proc head*(server: HttpServer, path: string, handler: Handler) =
  ## Register a HEAD route handler.
  server.route(HttpHead, path, handler)

proc options*(server: HttpServer, path: string, handler: Handler) =
  ## Register an OPTIONS route handler.
  server.route(HttpOptions, path, handler)

proc notFound*(server: HttpServer, handler: Handler) =
  ## Register a catch-all handler for unmatched routes.
  server.fallback = handler

# ── Listen ───────────────────────────────────────────────────────────────────

proc listen*(server: HttpServer, address: string, port: int) =
  ## Bind and start accepting HTTP connections.
  server.tcpServer = newTcpServer(server.loop,
    onAccept = proc(conn: Connection) =
      # Pre-create session
      server.sessions[conn.fd.int] = Session(parser: newHttpParser())
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      server.handleConnectionData(conn, data)
    ,
    onClose = proc(conn: Connection) =
      server.removeSession(conn.fd.int)
    ,
  )
  server.tcpServer.listen(address, port)

proc close*(server: HttpServer) =
  ## Shut down the server.
  if server.tcpServer != nil:
    server.tcpServer.close()
  server.sessions.clear()

proc ensureTcpServer*(server: HttpServer) =
  ## Lazily create the underlying TcpServer (for multi-thread use where
  ## listen() is called before routes are registered).
  if server.tcpServer != nil: return
  server.tcpServer = newTcpServer(server.loop,
    onAccept = proc(conn: Connection) =
      server.sessions[conn.fd.int] = Session(parser: newHttpParser())
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      server.handleConnectionData(conn, data)
    ,
    onClose = proc(conn: Connection) =
      server.removeSession(conn.fd.int)
    ,
  )

proc addConnection*(server: HttpServer, fd: SocketHandle) =
  ## Inject a pre-accepted client fd into this HTTP server's event loop.
  ## Used by multi-threaded acceptors that distribute connections to workers.
  server.ensureTcpServer()
  server.tcpServer.injectFd(fd)

proc getLoop*(server: HttpServer): Loop {.inline.} =
  ## Get the event loop associated with this server.
  server.loop
