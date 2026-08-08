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
