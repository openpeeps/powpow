## powpow/types.nim — Core types shared across all modules.

type
  EventType* = enum
    ## I/O event types reported by the platform backend.
    Read    ## fd is readable (data available or ready to accept)
    Write   ## fd is writable (output buffer has space)
    Error   ## Error condition on fd
    Hup     ## Peer closed connection / hangup detected

  Callback* = proc() {.closure.}
    ## Generic callback with no arguments, used for deferred calls and idle handlers.

  FdCallback* = proc(fd: int, events: set[EventType]) {.closure.}
    ## Callback invoked when I/O events fire on a registered fd.

  TimerCallback* = proc(id: int) {.closure.}
    ## Callback invoked when a timer expires. `id` is the timer identifier.

  TimerId* = distinct int
    ## Unique identifier for a registered timer.

proc `==`*(a, b: TimerId): bool {.borrow.}
