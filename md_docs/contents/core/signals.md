---
title: Signals
description: "The SignalRelay in-process pub/sub bus and OS signal delivery through the powpow event loop."
keywords: ["powpow", "signals", "sigint", "sigterm", "pubsub", "signalrelay"]
---

# Signals

powpow provides two related things in `signal.nim`:

1. **`SignalRelay`** — an in-process pub/sub event bus for named events.
2. **OS signal delivery** — real OS signals (SIGINT, SIGTERM, SIGHUP, …)
   delivered through the event loop, without global signal handlers.

Runnable examples: [`examples/signal_bus.nim`](../../examples/signal_bus.nim),
[`examples/os_signals.nim`](../../examples/os_signals.nim).

## SignalRelay: the in-process event bus

`SignalRelay` is an opaque handle (its type is internal, but it is returned by
the exported constructors). Events are addressed by an integer signal id; you
can also use `OsSignal` values as ids.

```nim
let relay = newSignalRelay(loop, maxSignals = 64)

# permanent subscriber
let handle = relay.listen(42, proc() = echo "event 42 fired")

# one-shot subscriber — auto-removed after the first event
relay.listenOnce(43, proc() = echo "event 43 fired (once)")

relay.emit(42)     # both 42 and 43 fire
relay.emit(43)     # only 42 fires — 43 already unsubscribed

unlisten(handle)   # or unlisten manually
```

`listen`/`listenOnce` return a `ListenerHandle`; call `unlisten(handle)` to
remove a subscriber early.

The `examples/signal_bus.nim` demo drives this from an HTTP endpoint
(`curl "http://localhost:9005/emit?signal=3"`).

## OS signals

`watchOsSignal`/`watchOsSignals` bridge real OS signals into the loop. Delivery
is platform-native with **no global signal handlers**:

- Linux: `signalfd`
- macOS / BSD / POSIX: self-pipe
- Windows: `SetConsoleCtrlHandler` (Ctrl+C)

```nim
let relay = newOsSignalRelay(loop)

relay.listen(SignalInt, proc() = echo "SIGINT — shutting down gracefully")
relay.listen(SignalTerm, proc() = echo "SIGTERM — shutting down gracefully")
relay.listen(SignalHup, proc() = echo "SIGHUP — reload config")

watchOsSignals(relay, [SignalInt, SignalTerm, SignalHup])
loop.run()
```

`OsSignal` enum:

| Value | Signal |
|---|---|
| `SignalHup` | SIGHUP |
| `SignalInt` | SIGINT |
| `SignalQuit` | SIGQUIT |
| `SignalUsr1` | SIGUSR1 |
| `SignalUsr2` | SIGUSR2 |
| `SignalPipe` | SIGPIPE |
| `SignalAlarm` | SIGALRM |
| `SignalTerm` | SIGTERM |
| `SignalUrgent` | SIGURG |
| `SignalChild` | SIGCHLD |
| `SignalIo` | SIGIO |

`signalNumber(s: OsSignal): cint` gives the raw platform number.

> [!NOTE]
> SIGPIPE is ignored globally by powpow on POSIX (the loop never crashes on a
> closed-socket write). SIGCHLD is delivered as an event; full child-process
> `waitpid` monitoring is on the [roadmap](../../plans/roadmap.md).

## Graceful shutdown pattern

```nim
relay.listen(SignalInt, proc() =
  server.stop()          # stop accepting
  loop.stop()            # stop the loop
  server.close()         # clean up after the loop has stopped
  loop.close())
```

See [`examples/os_signals.nim`](../../examples/os_signals.nim) for this exact flow.

## API reference

Full signatures: [signal API](../api/signal.md).
