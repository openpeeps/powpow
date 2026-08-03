## tests/test_signal.nim — Tests for the powpow Signal/Relay system.

import ../src/powpow
import std/unittest

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
