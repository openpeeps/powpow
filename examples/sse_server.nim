## examples/sse_server.nim — Server-Sent Events ticker.
##
## Demonstrates chunked streaming: `/events` opens a `text/event-stream`
## response and pushes a tick every second from a loop timer, long after the
## handler returned. `/` serves a tiny EventSource page; any other path 404s.
##
## Run:
##   nim c -r examples/sse_server.nim
##
## Test:
##   curl -N http://localhost:9007/events
##   open http://localhost:9007/ in a browser and watch the ticks arrive

import ../src/powpow
import std/httpcore except HttpMethod

const SsePort = 9007

let loop = newLoop()
let server = newHttpServer(loop)

var tick = 0

server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  {.gcsafe.}:
    let path = req.getPath()
    if path == "/events":
      let s = res.startSse()
      s.sendComment("connected")
      # Push ticks from the loop so the handler can return immediately;
      # the SseStream handle keeps the chunked response alive.
      var timer: TimerId
      timer = loop.addInterval(1000) do (id: int):
        inc tick
        if tick > 5:
          loop.cancelTimer(timer)
          s.sendEvent("bye", event = "done", id = $tick)
          s.close()
        else:
          s.sendEvent("tick " & $tick, event = "tick", id = $tick)
    elif path == "/":
      res.status(Http200)
        .header("Content-Type", "text/html; charset=utf-8")
        .send("""<html><body><ul id="log"></ul><script>
const es = new EventSource("/events");
es.addEventListener("tick", e => {
  const li = document.createElement("li");
  li.textContent = e.data + " (id " + e.lastEventId + ")";
  document.getElementById("log").appendChild(li);
});
es.addEventListener("done", e => { es.close(); });
</script></body></html>""")
    else:
      res.sendError(Http404, "404 Not Found: " & path)

echo "SSE ticker on http://localhost:" & $SsePort & "/events (Ctrl+C to stop)"
server.start(server.handler, Port(SsePort))
