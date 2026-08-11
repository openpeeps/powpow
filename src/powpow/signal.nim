# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/signal.nim — In-process signal/event relay AND OS signal delivery.
##
## `SignalRelay` is a small pub/sub bus: `relay.emit(signalId)` defers the
## subscribed callbacks onto the event loop (safe to call from any callback).
##
## `watchOsSignal` bridges real OS signals (SIGINT, SIGTERM, SIGHUP, SIGQUIT,
## SIGUSR1/2, SIGIO, SIGCHLD, ...) into the relay, so
##
##   let relay = newOsSignalRelay(loop)
##   discard relay.listen(SignalInt) do (): loop.stop()
##   relay.watchOsSignals([SignalInt, SignalTerm])
##
## delivers those signals through the loop instead of the default action.
## Delivery is platform-native, with no global signal handlers:
## - Linux:        signalfd (the signals are blocked and queued to an fd)
## - macOS / BSD:  self-pipe — a minimal async-signal-safe sigaction handler
##                 forwards the signal through a pipe registered on the loop
##                 (the same approach libuv uses; kqueue EVFILT_SIGNAL proved
##                 unreliable for a second blocked+pending signal)
## - other POSIX:  self-pipe (as above)
## - Windows:      SetConsoleCtrlHandler maps Ctrl+C to a synthetic SIGINT
##
## SIGKILL / SIGSTOP cannot be caught; SIGSEGV / SIGABRT / SIGILL / SIGFPE /
## SIGBUS / SIGTRAP are intentionally not exposed (they indicate bugs and
## should crash).

import std/tables
import ./loop, ./types

# ── OS signal enum ────────────────────────────────────────────────────────────

type
  OsSignal* = enum
    SignalHup     = 1   ## SIGHUP  — hangup / daemon reload
    SignalInt     = 2   ## SIGINT  — Ctrl+C
    SignalQuit    = 3   ## SIGQUIT — Ctrl+\
    SignalUsr1    = 10  ## SIGUSR1 — user-defined 1 (Linux 10, macOS/BSD 30)
    SignalUsr2    = 12  ## SIGUSR2 — user-defined 2 (Linux 12, macOS/BSD 31)
    SignalPipe    = 13  ## SIGPIPE — write to a closed pipe/socket (SIG_IGN by default in powpow)
    SignalAlarm   = 14  ## SIGALRM — alarm clock
    SignalTerm    = 15  ## SIGTERM — termination request
    SignalUrgent  = 16  ## SIGURG  — urgent data on a socket
    SignalChild   = 17  ## SIGCHLD — child stopped/exited (Linux 17, macOS/BSD 20)
    SignalIo      = 29  ## SIGIO   — async I/O ready (Linux 29, macOS/BSD 23)

proc signalNumber*(s: OsSignal): cint =
  ## Numeric signal value on the current platform.
  when defined(macosx) or defined(bsd):
    case s
    of SignalUsr1: 30
    of SignalUsr2: 31
    of SignalChild: 20
    of SignalIo: 23
    else: s.ord.cint
  else:
    s.ord.cint

# ── SignalRelay (in-process bus) ──────────────────────────────────────────────

type
  SignalListener = object
    cb: Callback
    once: bool
    id: int

  ListenerHandle* = ref object
    relay: SignalRelay
    signalId: int
    id: int
    alive: bool

  SignalRelay   = ref object
    loop: Loop
    listeners: seq[seq[SignalListener]]
    nextId: int

proc newSignalRelay*(loop: Loop, maxSignals: int): SignalRelay =
  SignalRelay(
    loop: loop,
    listeners: newSeq[seq[SignalListener]](maxSignals),
    nextId: 1,
  )

proc newOsSignalRelay*(loop: Loop): SignalRelay =
  ## A relay sized to cover real OS signal numbers (including SIGTERM = 15).
  newSignalRelay(loop, 32)

proc listen*(relay: SignalRelay, signalId: int, cb: Callback): ListenerHandle =
  let id = relay.nextId
  inc relay.nextId
  relay.listeners[signalId].add(SignalListener(cb: cb, once: false, id: id))
  ListenerHandle(relay: relay, signalId: signalId, id: id, alive: true)

proc listen*(relay: SignalRelay, signal: OsSignal, cb: Callback): ListenerHandle =
  ## Listen to an OS signal (maps to the platform's numeric signal value).
  relay.listen(int(signal.signalNumber), cb)

proc listenOnce*(relay: SignalRelay, signalId: int, cb: Callback): ListenerHandle =
  let id = relay.nextId
  inc relay.nextId
  relay.listeners[signalId].add(SignalListener(cb: cb, once: true, id: id))
  ListenerHandle(relay: relay, signalId: signalId, id: id, alive: true)

proc listenOnce*(relay: SignalRelay, signal: OsSignal, cb: Callback): ListenerHandle =
  relay.listenOnce(int(signal.signalNumber), cb)

proc unlisten*(li: ListenerHandle) =
  if not li.alive: return
  li.alive = false
  var i = 0
  while i < li.relay.listeners[li.signalId].len:
    if li.relay.listeners[li.signalId][i].id == li.id:
      li.relay.listeners[li.signalId].delete(i)
      return
    inc i

proc emit*(relay: SignalRelay, signalId: int) =
  if signalId < 0 or signalId >= relay.listeners.len:
    return
  let listeners = addr relay.listeners[signalId]
  if listeners[].len == 0:
    return
  let snapshot = listeners[]
  for li in snapshot:
    if li.once:
      var i = 0
      while i < listeners[].len:
        if listeners[][i].id == li.id:
          listeners[].delete(i)
          break
        inc i
    relay.loop.deferCall(li.cb)

# ── Platform signal plumbing ──────────────────────────────────────────────────

when defined(linux):
  import std/posix
  var SIG_BLOCK* {.importc: "SIG_BLOCK", header: "<signal.h>".}: cint
  proc sigprocmask(how: cint; set, oldset: ptr Sigset): cint {.
    importc: "sigprocmask", header: "<signal.h>".}
  proc c_read(fd: cint; buf: pointer; count: csize_t): csize_t {.
    importc: "read", header: "<unistd.h>".}
  proc c_close(fd: cint): cint {.importc: "close", header: "<unistd.h>".}

  type SignalfdSiginfo {.importc: "struct signalfd_siginfo",
      header: "<sys/signalfd.h>", pure, final.} = object
    ssi_signo: uint32
    ssi_errno: int32
    ssi_code: int32
    ssi_pid: uint32
    ssi_uid: uint32
    ssi_fd: int32
    ssi_tid: uint32
    ssi_band: uint32
    ssi_overrun: uint32
    ssi_trapno: uint32
    ssi_status: int32
    ssi_int: int32
    ssi_ptr: uint64
    ssi_utime: int64
    ssi_stime: int64
    ssi_addr: uint64
    ssi_addr_lsb: uint16

  proc signalfd(fd: cint; mask: ptr Sigset; flags: cint): cint {.
    importc: "signalfd", header: "<sys/signalfd.h>".}

elif defined(windows):
  import std/winlean
  type HandlerRoutine = proc(dwCtrlType: DWORD): int32 {.stdcall.}
  proc SetConsoleCtrlHandler(handler: HandlerRoutine; add: WINBOOL): WINBOOL {.
    importc: "SetConsoleCtrlHandler", dynlib: "kernel32".}
  const CTRL_C_EVENT = 0
  const WinSigInt = 2

else:
  # macOS / BSD / other POSIX: the self-pipe trick (a minimal sigaction handler
  # forwards the signal number through a pipe registered on the loop). This is
  # the approach libuv uses on macOS — kqueue EVFILT_SIGNAL turned out to be
  # unreliable here (a blocked, pending second signal was silently not
  # reported after prior loop activity).
  import std/posix
  var SA_RESTART* {.importc: "SA_RESTART", header: "<signal.h>".}: cint
  var gSelfPipeWr: cint = -1

  proc selfPipeHandler(sig: cint) {.noconv.} =
    ## Async-signal-safe: forwards the signal number through the pipe.
    if gSelfPipeWr >= 0:
      let b = byte(sig)
      discard write(gSelfPipeWr, addr b, 1)

# ── SignalSource (per-loop OS delivery) ───────────────────────────────────────

type
  SignalSource   = ref object of RootObj
    loop: Loop
    subscribers: Table[int, seq[SignalRelay]]
    armedSigs: seq[int]
    when defined(linux):
      sfFd: cint
      sfMask: Sigset
    elif defined(windows):
      consoleAdded: bool
    else:
      pipeRd: cint
      pipeWr: cint
      handlers: seq[(cint, Sigaction)]

proc onSignal(src: SignalSource, sig: int) =
  let relays = src.subscribers.getOrDefault(sig)
  for r in relays:
    r.emit(sig)

when defined(linux):
  proc ensureSignalfd(src: SignalSource) =
    if src.sfFd >= 0: return
    discard sigemptyset(src.sfMask)
    src.sfFd = signalfd(-1, addr src.sfMask, O_NONBLOCK or O_CLOEXEC)
    if src.sfFd < 0:
      raise newException(OSError, "powpow: signalfd() failed")
    src.loop.register(src.sfFd.int, {Read},
      edgeTriggered = true,
      callback = proc(fd: int, ev: set[EventType]) =
        if Read in ev:
          var info: SignalfdSiginfo
          while true:
            let n = c_read(fd.cint, addr info, sizeof(info).csize_t)
            if n != sizeof(info).csize_t:
              break
            src.onSignal(int(info.ssi_signo))
    )

  proc armSignal(src: SignalSource, sig: int) =
    src.ensureSignalfd()
    discard sigaddset(src.sfMask, sig.cint)
    discard signalfd(src.sfFd, addr src.sfMask, 0)   # update the watched mask
    discard sigprocmask(SIG_BLOCK, addr src.sfMask, nil)

elif defined(windows):
  var gWinLoop: Loop
  proc consoleHandler(dwCtrlType: DWORD): int32 {.stdcall.} =
    if dwCtrlType == CTRL_C_EVENT:
      let loop = gWinLoop
      if loop != nil:
        loop.postToLoop(proc() =
          let src = cast[SignalSource](loop.sigSource)
          if src != nil:
            src.onSignal(WinSigInt)
        )
    return 1  # handled

  proc armSignal(src: SignalSource, sig: int) =
    if not src.consoleAdded:
      gWinLoop = src.loop
      discard SetConsoleCtrlHandler(consoleHandler, 1)
      src.consoleAdded = true

else:
  proc ensurePipe(src: SignalSource) =
    if src.pipeRd >= 0: return
    var fds: array[2, cint]
    if pipe(fds) != 0:
      raise newException(OSError, "powpow: pipe() failed for signal handling")
    src.pipeRd = fds[0]
    src.pipeWr = fds[1]
    gSelfPipeWr = fds[1]
    var fl = fcntl(fds[0], F_GETFL, 0)
    if fl >= 0: discard fcntl(fds[0], F_SETFL, fl or O_NONBLOCK)
    fl = fcntl(fds[1], F_GETFL, 0)
    if fl >= 0: discard fcntl(fds[1], F_SETFL, fl or O_NONBLOCK)
    src.loop.register(fds[0].int, {Read},
      edgeTriggered = true,
      callback = proc(fd: int, ev: set[EventType]) =
        if Read in ev:
          var buf: array[16, byte]
          while true:
            let n = read(fd.cint, addr buf[0], buf.len)
            if n <= 0: break
            for i in 0 ..< n:
              src.onSignal(int(buf[i]))
    )

  proc armSignal(src: SignalSource, sig: int) =
    src.ensurePipe()
    var act: Sigaction
    act.sa_handler = selfPipeHandler
    discard sigemptyset(act.sa_mask)
    act.sa_flags = SA_RESTART.cint
    var old: Sigaction
    if sigaction(sig.cint, act, addr old) == 0:
      src.handlers.add((sig.cint, old))

proc teardown(src: SignalSource) =
  # Note: on signalfd (Linux) the armed signals are left BLOCKED after
  # teardown. Unblocking would deliver any still-pending signal, which then
  # hits its default action (e.g. SIGINT kills the process) during shutdown.
  # Keeping them blocked is safe — once a loop stops watching a signal, that
  # signal is simply held pending instead of terminating us.
  when defined(linux):
    if src.sfFd >= 0:
      src.loop.unregister(src.sfFd.int)
      discard c_close(src.sfFd)
      src.sfFd = -1
  elif defined(windows):
    if src.consoleAdded:
      discard SetConsoleCtrlHandler(consoleHandler, 0)
  else:
    if src.pipeRd >= 0:
      src.loop.unregister(src.pipeRd.int)
      discard close(src.pipeRd)
      discard close(src.pipeWr)
    for (sig, old) in src.handlers:
      var o = old
      discard sigaction(sig, o)

proc getSigSource(loop: Loop): SignalSource =
  if loop.sigSource == nil:
    let src = SignalSource(
      loop: loop,
      subscribers: initTable[int, seq[SignalRelay]](),
      armedSigs: @[],
    )
    when defined(linux):
      src.sfFd = -1
    elif defined(windows):
      discard
    else:
      src.pipeRd = -1
      src.pipeWr = -1
    loop.sigSource = src
    loop.addCleanup(proc() = teardown(src))
    result = src
  else:
    result = cast[SignalSource](loop.sigSource)

proc watchOsSignal*(relay: SignalRelay, signal: OsSignal) =
  ## Deliver the OS signal `signal` to `relay` (as `relay.emit(signal)` on the
  ## loop). Idempotent. Requires a relay sized past the numeric signal value —
  ## `newOsSignalRelay` covers all signals.
  let sig = signal.signalNumber
  let src = relay.loop.getSigSource()
  let relays = addr src.subscribers.mgetOrPut(sig, @[])
  if relays[].find(relay) < 0:
    relays[].add(relay)
  if sig notin src.armedSigs:
    src.armedSigs.add(sig)
    armSignal(src, sig)

proc watchOsSignals*(relay: SignalRelay, signals: openArray[OsSignal]) =
  ## Deliver each OS signal in `signals` to `relay`.
  for s in signals:
    relay.watchOsSignal(s)
