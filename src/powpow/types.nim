# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/types.nim — Core types shared across all modules.

type
  EventType* = enum
    Read
    Write
    Error
    Hup

  TlsState* = enum
    TlsOff
    TlsHandshaking
    TlsActive

  Callback* = proc() {.closure.}
  FdCallback* = proc(fd: int, events: set[EventType]) {.closure.}
  TimerCallback* = proc(id: int) {.closure.}
  ObserverCallback* = proc(value: uint64) {.closure.}
  TimerId* = distinct int

proc `==`*(a, b: TimerId): bool {.borrow.}
