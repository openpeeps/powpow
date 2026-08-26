---
title: Stream pipe (socketpair)
description: "IoStream duplex pair with half-close and EOF observation."
keywords: ["powpow", "example", "stream_pipe"]
---

# Stream pipe (socketpair)

Creates a full-duplex `IoStream` pair with `newStreamPair`. End A sends three messages on an interval, end B echoes each back, then A half-closes with `closeAfterWrite` so B observes EOF and ends the demo. Zero sockets involved: pure fd streaming.

Source: [`examples/stream_pipe.nim`](../../examples/stream_pipe.nim)

```nim
# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## examples/stream_pipe.nim — IoStream raw-fd streaming demo.
##
## Creates a full-duplex socketpair with `newStreamPair`: end A sends three
## messages, end B echoes each one back, then A half-closes with
## `closeAfterWrite` so B observes EOF (`onClose`).
##
## Run:
##   nim c -r examples/stream_pipe.nim

import ../src/powpow

proc toStr(data: openArray[byte]): string =
  ## Copy the received chunk into a string (cast[string] on an openArray is
  ## not valid — it would misread the length header in the buffer).
  result = newString(data.len)
  if data.len > 0:
    copyMem(addr result[0], unsafeAddr data[0], data.len)

let loop = newLoop()

var a, b: IoStream
(a, b) = newStreamPair(loop,
  # end A: prints the echoes that come back
  onData = proc(s: IoStream, data: openArray[byte]) =
    echo "  a received: ", data.toStr()
  ,
  # end B: echoes what it receives, and reports EOF when A closes
  onData2 = proc(s: IoStream, data: openArray[byte]) =
    echo "  b received: ", data.toStr()
    discard b.write("echo: " & data.toStr())
  ,
  onClose2 = proc(s: IoStream) =
    echo "  b saw EOF from a"
    loop.stop()
)

# End A sends three messages, then half-closes so B sees EOF.
var n = 0
discard loop.addInterval(400) do (id: int):
  inc n
  let msg = "message " & $n
  echo "a -> ", msg
  discard a.write(msg)
  if n == 3:
    loop.cancelTimer(TimerId(id))
    a.closeAfterWrite()

# Safety timeout — don't hang forever.
discard loop.addTimer(5000) do (id: int):
  loop.stop()

loop.run()

# After the loop stops, tear down both ends.
a.close()
b.close()
loop.close()
echo "bye"
```

## Running

```bash
nim c -r examples/stream_pipe.nim
```

## How it works

- `newStreamPair(loop, onData=..., onData2=..., onClose2=...)` wires both directions in one call.
- `a.write(msg)` queues bytes; `a.closeAfterWrite()` flushes then half-closes so the peer sees EOF rather than reset.
- Copy openArray payloads into a string with `copyMem`; casting an openArray slice to string misreads length headers.
- Safety timeout cancels the demo if anything wedges; teardown order is streams first, loop last.

[streams API](../api/stream.md).

