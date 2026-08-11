## tests/test_signal.nim — Tests for the powpow Signal/Relay system.

import ../src/powpow
import std/unittest
when not defined(windows):
  import std/posix as osposix

suite "signal":

  test "test_signal_listen_repeating":
    var count = 0
    let loop = newLoop()
    let relay = newSignalRelay(loop, 3)
    discard relay.listen(0) do ():
      inc count
    discard loop.addTimer(10) do (id: int):
      relay.emit(0)
    discard loop.addTimer(30) do (id: int):
      loop.stop()
    loop.run()
    check count == 1

  test "test_signal_listen_multiple_emits":
    var count = 0
    let loop = newLoop()
    let relay = newSignalRelay(loop, 3)
    discard relay.listen(0) do ():
      inc count
    var emitCount = 0
    discard loop.addInterval(10) do (id: int):
      if emitCount < 3:
        relay.emit(0)
        inc emitCount
      else:
        loop.cancelTimer(TimerId(id))
        loop.stop()
    loop.run()
    check count == 3

  test "test_signal_listen_once":
    var count = 0
    let loop = newLoop()
    let relay = newSignalRelay(loop, 3)
    discard relay.listenOnce(1) do ():
      inc count
    discard loop.addTimer(10) do (id: int):
      relay.emit(1)
    discard loop.addTimer(30) do (id: int):
      loop.stop()
    loop.run()
    check count == 1

  test "test_signal_listen_once_twice":
    var count = 0
    let loop = newLoop()
    let relay = newSignalRelay(loop, 3)
    discard relay.listenOnce(1) do ():
      inc count
    var emitCount = 0
    discard loop.addInterval(10) do (id: int):
      if emitCount < 2:
        relay.emit(1)
        inc emitCount
      else:
        loop.cancelTimer(TimerId(id))
        loop.stop()
    loop.run()
    check count == 1

  test "test_signal_unlisten":
    var count = 0
    let loop = newLoop()
    let relay = newSignalRelay(loop, 3)
    let li = relay.listen(0) do ():
      inc count
    li.unlisten()
    discard loop.addTimer(10) do (id: int):
      relay.emit(0)
    discard loop.addTimer(30) do (id: int):
      loop.stop()
    loop.run()
    check count == 0

  test "test_signal_no_listeners":
    let loop = newLoop()
    let relay = newSignalRelay(loop, 3)
    discard loop.addTimer(10) do (id: int):
      relay.emit(0)
      relay.emit(1)
    discard loop.addTimer(30) do (id: int):
      loop.stop()
    loop.run()
    check true

  test "test_signal_multiple_listeners":
    var count = 0
    let loop = newLoop()
    let relay = newSignalRelay(loop, 3)
    discard relay.listen(0) do (): inc count
    discard relay.listen(0) do (): inc count
    discard relay.listen(0) do (): inc count
    discard loop.addTimer(10) do (id: int):
      relay.emit(0)
    discard loop.addTimer(30) do (id: int):
      loop.stop()
    loop.run()
    check count == 3

  test "test_signal_multiple_signals":
    var a, b = 0
    let loop = newLoop()
    let relay = newSignalRelay(loop, 3)
    discard relay.listen(0) do (): inc a
    discard relay.listen(1) do (): inc b
    discard loop.addTimer(10) do (id: int):
      relay.emit(0)
    discard loop.addTimer(30) do (id: int):
      loop.stop()
    loop.run()
    check a == 1
    check b == 0

  test "test_signal_unlisten_from_callback":
    var a, b = 0
    let loop = newLoop()
    let relay = newSignalRelay(loop, 3)
    let liB = relay.listen(0) do (): inc b
    discard relay.listen(0) do ():
      inc a
      liB.unlisten()
    discard loop.addTimer(10) do (id: int):
      relay.emit(0)
    discard loop.addTimer(30) do (id: int):
      loop.stop()
    loop.run()
    check a == 1
    check b == 1  # B fires once (already deferred before A unlistened it)

when not defined(windows):
  # ── OS signal delivery (SIGUSR1/SIGUSR2 are the safest for CI) ─────────────

  test "test_os_signal_delivered":
    # SIGUSR1 sent to our own process must reach a relay listener on the loop,
    # and the process must keep running (default action suppressed).
    var count = 0
    let loop = newLoop()
    let relay = newOsSignalRelay(loop)
    discard relay.listen(SignalUsr1) do (): inc count
    relay.watchOsSignal(SignalUsr1)
    discard loop.addTimer(10) do (id: int):
      discard osposix.kill(osposix.getpid(), osposix.SIGUSR1)
    discard loop.addTimer(50) do (id: int):
      check count == 1
      loop.stop()
    loop.run()
    check count == 1
    loop.close()

  test "test_os_signal_multiple":
    var a, b = 0
    let loop = newLoop()
    let relay = newOsSignalRelay(loop)
    discard relay.listen(SignalUsr1) do (): inc a
    discard relay.listen(SignalUsr2) do (): inc b
    relay.watchOsSignals([SignalUsr1, SignalUsr2])
    discard loop.addTimer(10) do (id: int):
      discard osposix.kill(osposix.getpid(), osposix.SIGUSR1)
      discard osposix.kill(osposix.getpid(), osposix.SIGUSR2)
    discard loop.addTimer(50) do (id: int):
      loop.stop()
    loop.run()
    check a == 1
    check b == 1
    loop.close()

  test "test_os_signal_sigint":
    # The primary shutdown case: SIGINT must be delivered, not terminate us.
    var count = 0
    let loop = newLoop()
    let relay = newOsSignalRelay(loop)
    discard relay.listen(SignalInt) do (): inc count
    relay.watchOsSignal(SignalInt)
    discard loop.addTimer(10) do (id: int):
      discard osposix.kill(osposix.getpid(), osposix.SIGINT)
    discard loop.addTimer(50) do (id: int):
      loop.stop()
    loop.run()
    check count == 1
    loop.close()

  test "test_os_signal_listen_once":
    var count = 0
    let loop = newLoop()
    let relay = newOsSignalRelay(loop)
    discard relay.listenOnce(SignalUsr1) do (): inc count
    relay.watchOsSignal(SignalUsr1)
    discard loop.addTimer(10) do (id: int):
      discard osposix.kill(osposix.getpid(), osposix.SIGUSR1)
      discard osposix.kill(osposix.getpid(), osposix.SIGUSR1)
    discard loop.addTimer(50) do (id: int):
      loop.stop()
    loop.run()
    check count == 1
    loop.close()

  test "test_os_signal_unlisten":
    var count = 0
    let loop = newLoop()
    let relay = newOsSignalRelay(loop)
    let li = relay.listen(SignalUsr1) do (): inc count
    relay.watchOsSignal(SignalUsr1)
    li.unlisten()
    discard loop.addTimer(10) do (id: int):
      discard osposix.kill(osposix.getpid(), osposix.SIGUSR1)
    discard loop.addTimer(50) do (id: int):
      loop.stop()
    loop.run()
    check count == 0
    loop.close()

  test "test_os_signal_watched_no_listener":
    # A watched signal with no subscribed listener is still caught (the default
    # action is suppressed) but fires nothing — and must not kill the process.
    var count = 0
    let loop = newLoop()
    let relay = newOsSignalRelay(loop)
    relay.watchOsSignal(SignalUsr1)   # armed, but no listen() subscribed
    discard loop.addTimer(10) do (id: int):
      discard osposix.kill(osposix.getpid(), osposix.SIGUSR1)
    discard loop.addTimer(50) do (id: int):
      loop.stop()
    loop.run()
    check count == 0
    loop.close()
