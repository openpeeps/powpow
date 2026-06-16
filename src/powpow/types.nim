# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/types.nim — Core types shared across all modules.

type
  EventType* = enum
    Read
    Write
    Error
    Hup

  Callback* = proc() {.closure.}
  FdCallback* = proc(fd: int, events: set[EventType]) {.closure.}
  TimerCallback* = proc(id: int) {.closure.}
  TimerId* = distinct int

proc `==`*(a, b: TimerId): bool {.borrow.}
