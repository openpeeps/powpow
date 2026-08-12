---
title: Getting started
description: "Install powpow, write your first HTTP and WebSocket server, and learn the build flags and conventions."
keywords: ["powpow", "getting started", "install", "first server", "hello world"]
---

# Getting started

## Requirements

- Nim **>= 2.2.0**
- `nimble` (comes with Nim)

Dependencies are resolved automatically by nimble:

- `nimsimd >= 1.3.2`
- `mimedb >= 0.1.1`
- `openparser >= 0.1.8`
- `multipart >= 0.1.4`
- `checksums >= 0.2.2`

## Installation

```bash
nimble install powpow
```

For a local checkout, from the repository root:

```bash
nimble install -Y
```

## Your first HTTP server

```nim
import powpow

let server = newHttpServer()          # creates its own loop

proc handler(req: HttpRequest, res: HttpResponse) {.gcsafe.} =
  if req.getPath() == "/":
    res.status(Http200)
       .header("Content-Type", "text/html; charset=utf-8")
       .send("<h1>Hello from powpow!</h1>")
  else:
    res.sendError(Http404)

server.start(handler, Port(9000))
```

Compile and run:

```bash
nim c -r -d:release myserver.nim
curl http://localhost:9000/
```

That's the whole library surface in one handler: `req` gives you the parsed
request, `res` is a fluent response builder.

## Your first WebSocket server

```nim
import powpow

let wss = newWsServer()
wss.onMessage(proc(ws: WsConnection, kind: WsFrameKind, data: openArray[byte]) =
  ws.sendText("echo: " & cast[string](data)))

wss.start()
wss.listen("0.0.0.0", 9001)
```

```bash
nim c -r -d:release wsdemo.nim
websocat ws://localhost:9001
```

## Running the examples

Every example in [`examples/`](../examples/) is runnable:

```bash
nim c -r examples/httpserver.nim          # HTTP server on :9000
nim c -r --threads:on examples/httpserver_threads.nim   # multi-threaded on :9000
```

See the [examples index](examples.md) for the full list, ports and test
commands.

## Build flags and notes

- **`--threads:on`** — required for the multi-threaded server
  ([concurrency](concurrency.md)) and the thread-safety tests. The core event
  loop itself is single-threaded and does not require it.
- **`-d:release`** — always use release for benchmarking or real workloads.
- **`-d:powpowEnableMetrics`** — compile-time opt-in for event-loop metrics
  (roadmap item; not yet implemented).
- **Windows** — supported via IOCP, but TLS is not available on Windows and the
  WebSocket/file-watching feature set is less complete.
- **Unix domain sockets** — `listenUnix`/`connectUnix` are POSIX-only.

## Running the tests

```bash
nimble test            # the standard suite
nimble testThreads     # thread-safety smoke tests (--threads:on)
nimble testSmuggler    # parser fuzzing with the smuggler package (if installed)
```

See [testing](testing.md) for the full test-suite map.

## A note on routing

powpow deliberately ships **no router**. Routing is up to you — simple
`if`/`case` on `getPath()`, or a framework such as
[Supranim](https://github.com/supranim/supranim) built on top of powpow's
`OnRequestCallback`. See the [HTTP server guide](http/server.md) for the routing
idioms used by the examples.

## Where to go next

- [Overview](overview.md) — architecture and the full feature matrix
- [Event loop](core/event-loop.md) — the foundation everything sits on
- [HTTP server](http/server.md) — routing, responses, config
- [Examples index](examples.md) — 19 runnable programs
