---
title: File system watcher
description: "Watch a path for modify/rename/delete/attrib events on the loop."
keywords: ["powpow", "example", "fswatch"]
---

# File system watcher

Registers a watcher on `/tmp/powpow-test.txt` and prints every event set delivered through the loop. Uses the platform backend (inotify/kqueue/polling) behind one portable callback signature.

Source: [`examples/fswatch.nim`](../../examples/fswatch.nim)

```nim
## examples/fswatch.nim — File system watcher demo.
##
## Run:
##   nim c -r examples/fswatch.nim
##
## Then in another terminal:
##   echo "hello" >> /tmp/powpow-test.txt
##   mv /tmp/powpow-test.txt /tmp/powpow-test2.txt
##   rm /tmp/powpow-test2.txt

import ../src/powpow
import std/[os, posix]

let loop = newLoop()

# Create a test file
writeFile("/tmp/powpow-test.txt", "test\n")

echo "Watching /tmp/powpow-test.txt for changes..."
echo "Try: echo 'hello' >> /tmp/powpow-test.txt"

let w = newFileWatcher(loop, "/tmp/powpow-test.txt") do (w: FileWatcher, events: set[FileSystemEvent]):
  echo "Event on ", w.path, ": ", events
  if fseModified in events:
    echo "  → file was modified"
  if fseDeleted in events:
    echo "  → file was deleted"
  if fseRenamed in events:
    echo "  → file was renamed"
  if fseAttrib in events:
    echo "  → attributes changed"

if w == nil:
  echo "ERROR: Failed to create file watcher"
  quit(1)

discard loop.addTimer(30_000) do (id: int):
  echo "Timeout — stopping"
  w.close()
  loop.stop()

echo "Running loop for 30 seconds..."
loop.run()
echo "Done"
```

## Running

```bash
nim c -r examples/fswatch.nim
```

## Try it

```bash
# in another terminal
echo hello >> /tmp/powpow-test.txt
mv /tmp/powpow-test.txt /tmp/powpow-test2.txt
rm /tmp/powpow-test2.txt
```

## How it works

- `newFileWatcher(loop, path) do (w, events)` receives a `set[FileSystemEvent]`: `fseModified`, `fseDeleted`, `fseRenamed`, `fseAttrib`.
- A nil watcher means registration failed (unsupported platform or bad path); the example aborts loudly.
- Self-terminates after 30 seconds via a timer that closes both the watcher and the loop.

[fswatch API](../api/fswatch.md).

