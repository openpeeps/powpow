---
title: signal
description: "The SignalRelay API: listen/listenOnce/unlisten/emit, the OsSignal enum and watchOsSignal(s)."
keywords: ["powpow", "api", "signal", "signalrelay", "ossignal"]
---

# signal

In-process `SignalRelay` pub/sub bus and OS signal delivery.
Source: `src/powpow/signal.nim`. Guide: [Signals](../core/signals.md).

## Enum

```nim
OsSignal* = enum
  SignalHup = 1,    # SIGHUP
  SignalInt = 2,    # SIGINT
  SignalQuit = 3,   # SIGQUIT
  SignalUsr1 = 10,  # SIGUSR1
  SignalUsr2 = 12,  # SIGUSR2
  SignalPipe = 13,  # SIGPIPE
  SignalAlarm = 14, # SIGALRM
  SignalTerm = 15,  # SIGTERM
  SignalUrgent = 16,# SIGURG
  SignalChild = 17, # SIGCHLD
  SignalIo = 29     # SIGIO
```

## Types

```nim
ListenerHandle* = ref object    # opaque; pass to unlisten()
SignalRelay                    # opaque handle, returned by constructors
```

## Procs

```nim
proc signalNumber*(s: OsSignal): cint

# relays
proc newSignalRelay*(loop: Loop, maxSignals: int): SignalRelay
proc newOsSignalRelay*(loop: Loop): SignalRelay

# pub/sub
proc listen*(relay: SignalRelay, signalId: int, cb: Callback): ListenerHandle
proc listen*(relay: SignalRelay, signal: OsSignal, cb: Callback): ListenerHandle
proc listenOnce*(relay: SignalRelay, signalId: int, cb: Callback): ListenerHandle
proc listenOnce*(relay: SignalRelay, signal: OsSignal, cb: Callback): ListenerHandle
proc unlisten*(li: ListenerHandle)
proc emit*(relay: SignalRelay, signalId: int)

# OS signals
proc watchOsSignal*(relay: SignalRelay, signal: OsSignal)
proc watchOsSignals*(relay: SignalRelay, signals: openArray[OsSignal])
```

## Exported vars (platform constants)

```nim
var SIG_BLOCK*: cint    # Linux only
var SA_RESTART*: cint   # macOS/BSD/POSIX only
```

## Related

- [loop](loop.md) — relays are driven by the loop
