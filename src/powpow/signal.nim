import ./loop, ./types

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

  SignalRelay* = ref object
    loop: Loop
    listeners: seq[seq[SignalListener]]
    nextId: int

proc newSignalRelay*(loop: Loop, maxSignals: int): SignalRelay =
  SignalRelay(
    loop: loop,
    listeners: newSeq[seq[SignalListener]](maxSignals),
    nextId: 1,
  )

proc listen*(relay: SignalRelay, signalId: int, cb: Callback): ListenerHandle =
  let id = relay.nextId
  inc relay.nextId
  relay.listeners[signalId].add(SignalListener(cb: cb, once: false, id: id))
  ListenerHandle(relay: relay, signalId: signalId, id: id, alive: true)

proc listenOnce*(relay: SignalRelay, signalId: int, cb: Callback): ListenerHandle =
  let id = relay.nextId
  inc relay.nextId
  relay.listeners[signalId].add(SignalListener(cb: cb, once: true, id: id))
  ListenerHandle(relay: relay, signalId: signalId, id: id, alive: true)

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
