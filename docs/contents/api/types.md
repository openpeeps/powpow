---
title: types
description: "Core shared types: EventType, TlsState, callbacks and TimerId."
keywords: ["powpow", "api", "types", "eventtype", "timerid"]
---

# types

Core types shared across all modules. Source: `src/powpow/types.nim`.

## Enums

```nim
EventType* = enum Read, Write, Error, Hup
TlsState*  = enum TlsOff, TlsHandshaking, TlsActive
```

## Callback types

```nim
Callback*        = proc() {.closure.}
FdCallback*      = proc(fd: int, events: set[EventType]) {.closure.}
TimerCallback*   = proc(id: int) {.closure.}
ObserverCallback* = proc(value: uint64) {.closure.}
```

## Timer id

```nim
TimerId* = distinct int
proc `==`*(a, b: TimerId): bool {.borrow.}
```

## Related

- [loop](loop.md) — where these are used
