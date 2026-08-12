## Headless-browser repro for the WsConnection pool use-after-free.
##
## Serves `/ws` (websocketUpgrade) and `/` (an HTML page whose script opens a
## WebSocket to /ws and reports its state via data attributes). Driving the page
## from headless Chrome repeatedly — each load opens a ws, Chrome exits and the
## ws closes, the next load opens a new ws — reproduces booyaka's "refresh the
## page" crash: the released ws is re-acquired while its block was freed (raw
## pointer pool did not retain it under ARC-family MM).
##
## Run:  nim c -d:release --mm:atomicArc -r tests/ws_refresh_server.nim
##       ./drive_refresh.sh    (headless Chrome loop against :9008)

import std/[httpcore, strutils]
import ../src/powpow

let loop = newLoop()
let server = newHttpServer(loop)
server.wsIdleTimeoutMs = 30_000

const Page = """<!doctype html><html><body data-ws="init"><script>
(async () => {
  try {
    const ws = new WebSocket('ws://127.0.0.1:9008/ws');
    await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej('error'); });
    document.body.dataset.ws = 'open';
  } catch (e) {
    document.body.dataset.ws = 'exception:' + String(e);
  }
})();
</script></body></html>"""

var gUpgrades = 0

server.handler = proc(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  debugEcho("request path=", req.getPath())
  if req.getPath() == "/ws":
    inc gUpgrades
    debugEcho("upgrade #", gUpgrades)
    # Churn WsConnection-shaped allocations so a freed pooled ws's block is
    # reused before the next acquireWs pops it (mimics app allocations like
    # booyaka's markdown rendering between refreshes).
    {.cast(gcsafe).}:
      let fakeConn = newConnection(SocketHandle(-1), loop, nil, acquireBuf(loop), DefaultBufSize)
      var churn: seq[WsConnection]
      for i in 0 ..< 300:
        churn.add(newWsConnection(fakeConn, 1024))
    discard websocketUpgrade(res, req,
      onOpen = proc(ws: WsConnection) =
        ws.sendText("welcome")
      ,
      onMessage = proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
        discard
      ,
    )
  else:
    res.status(Http200)
       .header("Content-Type", "text/html")
       .send(Page)

server.listen("127.0.0.1", 9008)
echo "listening on 127.0.0.1:9008"
loop.run()
server.close()
loop.close()
