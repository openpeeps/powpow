# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow


## Monitors file/directory changes using kqueue (macOS/BSD) or inotify (Linux).
## Integrates with the powpow event loop — no polling thread required.

import ./loop, ./types

when defined(macosx) or defined(bsd):
  import std/[kqueue, posix]
elif defined(linux):
  import std/posix

type
  FileSystemEvent* = enum
    fseModified
    fseCreated
    fseDeleted
    fseRenamed
    fseAttrib
    fseLinkCount
    fseRevoke

  FileWatcherCb* = proc(w: FileWatcher; events: set[FileSystemEvent]) {.closure.}

  FileWatcher* = ref object
    loop*:     Loop
    path*:     string
    callback*: FileWatcherCb
    when defined(macosx) or defined(bsd):
      kq:       int
      fileFd:   int
    elif defined(linux):
      inotifyFd: int
      watchWd:  int

when defined(macosx) or defined(bsd):
  const
    O_EVTONLY = 0x8000
    NOTE_DELETE = 0x0001
    NOTE_WRITE  = 0x0002
    NOTE_EXTEND = 0x0004
    NOTE_ATTRIB = 0x0008
    NOTE_LINK   = 0x0010
    NOTE_RENAME = 0x0020
    NOTE_REVOKE = 0x0040

  proc toFileEvents(fflags: uint32): set[FileSystemEvent] =
    if (fflags and NOTE_DELETE) != 0: result.incl fseDeleted
    if (fflags and NOTE_WRITE) != 0:  result.incl fseModified
    if (fflags and NOTE_EXTEND) != 0: result.incl fseModified
    if (fflags and NOTE_ATTRIB) != 0: result.incl fseAttrib
    if (fflags and NOTE_LINK) != 0:   result.incl fseLinkCount
    if (fflags and NOTE_RENAME) != 0: result.incl fseRenamed
    if (fflags and NOTE_REVOKE) != 0: result.incl fseRevoke

elif defined(linux):
  type
    InotifyEvent {.importc: "struct inotify_event", header: "<sys/inotify.h>",
                   pure, final.} = object
      wd:       int32
      mask:     uint32
      cookie:   uint32
      len:      uint32

  proc inotify_init1(flags: cint): cint {.
    importc: "inotify_init1", header: "<sys/inotify.h>".}
  proc inotify_add_watch(fd: cint; path: cstring; mask: uint32): cint {.
    importc: "inotify_add_watch", header: "<sys/inotify.h>".}
  proc inotify_rm_watch(fd: cint; wd: cint): cint {.
    importc: "inotify_rm_watch", header: "<sys/inotify.h>".}

  const IN_NONBLOCK = 0x800
  const
    IN_MODIFY      = 0x00000002
    IN_CREATE      = 0x00000100
    IN_DELETE      = 0x00000200
    IN_MOVED_FROM  = 0x00000040
    IN_MOVED_TO    = 0x00000080
    IN_ATTRIB      = 0x00000004
    IN_DELETE_SELF = 0x00000400
    IN_MOVE_SELF   = 0x00000800
    IN_IGNORED     = 0x00008000

  const InWatchMask = IN_MODIFY or IN_CREATE or IN_DELETE or
                      IN_MOVED_FROM or IN_MOVED_TO or
                      IN_ATTRIB or IN_DELETE_SELF or IN_MOVE_SELF

  proc toFileEvents(mask: uint32): set[FileSystemEvent] =
    if (mask and IN_MODIFY) != 0:      result.incl fseModified
    if (mask and IN_CREATE) != 0:      result.incl fseCreated
    if (mask and IN_DELETE) != 0:      result.incl fseDeleted
    if (mask and IN_DELETE_SELF) != 0: result.incl fseDeleted
    if (mask and IN_MOVED_FROM) != 0:  result.incl fseRenamed
    if (mask and IN_MOVED_TO) != 0:    result.incl fseRenamed
    if (mask and IN_MOVE_SELF) != 0:   result.incl fseRenamed
    if (mask and IN_ATTRIB) != 0:      result.incl fseAttrib
    if (mask and IN_IGNORED) != 0:     result.incl fseRevoke

proc newFileWatcher*(loop: Loop, path: string,
                     callback: FileWatcherCb): FileWatcher =
  when defined(macosx) or defined(bsd):
    let fileFd = posix.open(path, O_EVTONLY, 0)
    if fileFd < 0:
      return nil
    let kq = kqueue()
    if kq < 0:
      discard posix.close(fileFd)
      return nil

    var ev: KEvent
    ev.ident = fileFd.csize_t
    ev.filter = EVFILT_VNODE
    ev.flags = EV_ADD or EV_CLEAR
    ev.fflags = NOTE_WRITE or NOTE_DELETE or NOTE_RENAME or
                NOTE_ATTRIB or NOTE_EXTEND or NOTE_LINK
    ev.udata = nil
    ev.data = 0

    if kevent(kq, addr ev, 1, nil, 0, nil) < 0:
      discard posix.close(kq)
      discard posix.close(fileFd)
      return nil

    result = FileWatcher(
      loop: loop, path: path, callback: callback,
      kq: kq.int, fileFd: fileFd.int)
    let w = result

    loop.register(kq.int, {Read}) do (fd: int, ev: set[EventType]):
      if Read notin ev: return
      var kev: KEvent
      while true:
        let n = kevent(kq, nil, 0, addr kev, 1, nil)
        if n <= 0: break
        let fev = toFileEvents(kev.fflags)
        if fev != {}:
          callback(w, fev)

  elif defined(linux):
    let ifd = inotify_init1(IN_NONBLOCK)
    if ifd < 0:
      return nil
    let wd = inotify_add_watch(ifd, path, InWatchMask)
    if wd < 0:
      discard posix.close(ifd)
      return nil

    result = FileWatcher(
      loop: loop, path: path, callback: callback,
      inotifyFd: ifd.int, watchWd: wd.int)
    let w = result

    loop.register(ifd.int, {Read}) do (fd: int, ev: set[EventType]):
      if Read notin ev: return
      var buf: array[4096, byte]
      let n = posix.read(fd, addr buf[0], 4096)
      if n <= 0: return
      var off = 0
      while off < n:
        let ie = cast[ptr InotifyEvent](addr buf[off])
        let fev = toFileEvents(ie.mask)
        if fev != {}:
          callback(w, fev)
        off += sizeof(InotifyEvent) + ie.len.int

  else:
    discard

proc close*(w: FileWatcher) =
  if w == nil: return
  when defined(macosx) or defined(bsd):
    if w.kq >= 0:
      w.loop.unregister(w.kq)
      discard posix.close(w.kq.cint)
      w.kq = -1
    if w.fileFd >= 0:
      discard posix.close(w.fileFd.cint)
      w.fileFd = -1
  elif defined(linux):
    if w.inotifyFd >= 0:
      w.loop.unregister(w.inotifyFd)
      discard posix.close(w.inotifyFd.cint)
      w.inotifyFd = -1
