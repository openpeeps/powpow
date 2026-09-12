# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/types.nim — Core types shared across all modules.

import pkg/voodoo/extensibles
export extensibles

const
  iouEnabled* = defined(linux) and
    (defined(features.powpow.io_uring) or defined(powpowIoUring))
    ## Compile-time switch for the Linux io_uring backend. Activated via the
    ## nimble/clue `--features:io_uring` mechanism (which defines
    ## `features.powpow.io_uring`) or directly with `-d:powpowIoUring`.
    ## Linux-only: on other OSes the flag is a no-op and the default backend
    ## (epoll/kqueue/IOCP) is used, so passing `-d:powpowIoUring` on Windows or
    ## macOS cannot pull in the Linux-only io/uring module.
    ## Guard backend-specific code with `when iouEnabled:`.

type
  HttpMethod* {.extensible.} = enum
    ## HTTP request method. Mirrors `std/httpcore.HttpMethod` wire tokens and
    ## order so `$` stays compatible, but is extensible at compile time via
    ## `pkg/voodoo` (`extendEnum` + `extendCaseStmt` before importing powpow).
    ## WebDAV and other extensions register new verbs without forking powpow.
    HttpHead = "HEAD"
    HttpGet = "GET"
    HttpPost = "POST"
    HttpPut = "PUT"
    HttpDelete = "DELETE"
    HttpTrace = "TRACE"
    HttpOptions = "OPTIONS"
    HttpConnect = "CONNECT"
    HttpPatch = "PATCH"

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
