---
title: platform
description: "The platform API: the I/O multiplexer backends (kqueue, epoll, poll, iocp) and their common surface."
keywords: ["powpow", "api", "platform", "kqueue", "epoll", "iocp"]
---

# platform

Compile-time backend selector and the I/O multiplexer interface. Source:
`src/powpow/platform.nim` and `src/powpow/platform/{kqueue,epoll,poll,iocp}.nim`.
Guide: [event loop](../core/event-loop.md).

`platform.nim` selects the backend at compile time and re-exports it:

| Platform | Backend |
|---|---|
| Linux | `epoll` (with eventfd wake) |
| macOS / BSD | `kqueue` (edge-triggered) |
| Windows | `iocp` |
| anything else | `poll` |

`src/powpow.nim` re-exports `platform except close` (the `Loop.close` shadows
the backend's `close`).

## Types

```nim
PlatformEvent* = object
  fd*: int
  events*: set[EventType]
  udata*: pointer

Platform* = ref object
  events*: seq[PlatformEvent]
  count*: int
```

## Procs (identical across backends)

```nim
proc init*(T: typedesc[Platform]): T
proc close*(p: Platform)
proc ensureCapacity*(p: Platform, fdCount: int) {.inline.}
proc add*(p: Platform, fd: int, events: set[EventType], edgeTriggered = false, udata: pointer = nil)
proc remove*(p: Platform, fd: int)
proc modify*(p: Platform, fd: int, events: set[EventType], edgeTriggered = false, udata: pointer = nil)
proc wake*(p: Platform) {.inline.}
proc poll*(p: Platform, timeoutMs: int): int {.inline.}
```

## IOCP-only extras

```nim
proc getReadData*(p: Platform, fd: int, buf: ptr UncheckedArray[byte], bufLen: int): int
```

## Related

- [loop](loop.md) — owns a `Platform` and calls these
- [types](types.md) — `EventType`
