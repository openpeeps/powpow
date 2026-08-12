---
title: fswatch
description: "The FileWatcher API: newFileWatcher, close and the FileSystemEvent enum."
keywords: ["powpow", "api", "fswatch", "filewatcher", "filesystem"]
---

# fswatch

File/directory change monitoring via kqueue (macOS/BSD) or inotify (Linux),
integrated with the loop. Source: `src/powpow/fswatch.nim`.
Guide: [File system watching](../core/fswatch.md).

## Enum

```nim
FileSystemEvent* = enum
  fseModified, fseCreated, fseDeleted, fseRenamed,
  fseAttrib, fseLinkCount, fseRevoke
```

## Types

```nim
FileWatcherCb* = proc(w: FileWatcher; events: set[FileSystemEvent]) {.closure.}

FileWatcher* = ref object
  loop*: Loop
  path*: string
  callback*: FileWatcherCb
```

## Procs

```nim
proc newFileWatcher*(loop: Loop, path: string, callback: FileWatcherCb): FileWatcher
proc close*(w: FileWatcher)
```

## Related

- [loop](loop.md) — watchers run on the loop
