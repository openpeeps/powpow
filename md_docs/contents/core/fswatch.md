---
title: File system watching
description: "Monitor files and directories on the powpow loop with FileWatcher (kqueue on macOS/BSD, inotify on Linux)."
keywords: ["powpow", "fswatch", "file watching", "inotify", "kqueue"]
---

# File system watching

`fswatch.nim` exposes a `FileWatcher` that monitors a file or directory for
changes, integrated with the event loop — no polling, no extra threads.

Runnable example: [`examples/fswatch.nim`](../../examples/fswatch.nim).

## Creating a watcher

```nim
let watcher = newFileWatcher(loop, "/tmp/powpow-test.txt", proc(w: FileWatcher; events: set[FileSystemEvent]) =
  if fseModified in events:
    echo "modified"
  if fseDeleted in events:
    echo "deleted"))
```

The callback receives the watcher and the set of events that fired.
`FileSystemEvent` values:

- `fseModified` — contents changed
- `fseCreated` — file created
- `fseDeleted` — file deleted
- `fseRenamed` — file renamed
- `fseAttrib` — attributes (permissions, times) changed
- `fseLinkCount` — hard-link count changed
- `fseRevoke` — access revoked

## Closing

```nim
watcher.close()
```

## Backends

| Platform | Mechanism |
|---|---|
| macOS / BSD | `kqueue` `EVFILT_VNODE` |
| Linux | `inotify` |
| Windows | not yet implemented |

The watcher is owned by the loop: it registers its fd with the loop and is
cleaned up via `addCleanup` when the loop closes.

## API reference

Full signatures: [fswatch API](../api/fswatch.md).
