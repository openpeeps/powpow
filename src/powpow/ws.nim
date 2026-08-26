# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## High-level WebSocket API: a self-managed client facade plus the standalone
## server, both reachable through a single import.
##
##   ```nim
##   import powpow/ws
##
##   let client = newWsClient()
##   client.onOpen do (ws: WsConnection):
##     ws.sendMessage("hello")
##   client.onMessage do (ws: WsConnection, kind: WsFrameKind,
##                        data: openArray[byte]):
##     echo cast[string](@data)
##   discard client.connect("wss://example.com/chat")
##   client.run()        # blocks; auto-reconnects per policy until close()
##   ```
##
## The client creates and owns its event loop internally (like
## `newWsServer()` without arguments): `connect()` arms everything, `run()`
## drives the loop on the calling thread. Failed handshakes and abnormal
## drops are retried automatically with exponential backoff and jitter;
## deliberate closes never trigger a reconnect.

import std/[random]

import ./loop
import ./net/tcp
import ./net/tls
import ./proto/ws

export loop, tls, ws

type
  WsReconnectPolicy* = object
    ## Reconnect behaviour for `WsClient`.
    maxRetries*: int        ## Consecutive failed attempts allowed before giving
                            ## up (-1 = unlimited). Successful connects reset
                            ## the counter.
    backoffStartMs*: int    ## Delay before the first retry (default 500 ms)
    backoffMaxMs*: int      ## Ceiling for the exponential backoff (10 s)
    jitter*: float          ## Fraction of randomization applied to each delay
                            ## (0..0.95); avoids synchronized reconnect storms

  WsRetryCb* = proc(attempt: int, delayMs: int) {.closure.}
    ## Fired before scheduling retry number `attempt`, which will run after
    ## roughly `delayMs` milliseconds.

  WsGiveUpCb* = proc(attempts: int) {.closure.}
    ## Fired once when the policy's `maxRetries` is exhausted; `run()` returns
    ## shortly afterwards.

  WsClient* = ref object
    ## High-level WebSocket client. Owns its private event loop; user
    ## callbacks survive reconnects. One session at a time: while connected
    ## or mid-attempt, further connect calls return false.
    loop: Loop
    policy: WsReconnectPolicy
    rng: Rand
    # Connection target
    tHost: string
    tPort: int
    tPath: string
    tlsCtx: SslContext
    extraHeaders: seq[(string, string)]
    protocols: seq[string]
    pingIntervalMs: int
    idleTimeoutMs: int
    maxFrameSize: int
    handshakeTimeoutMs: int
    # Persistent user callbacks
    cbOpen: WsOpenCb
    cbMsg: WsMessageCb
    cbClose: WsCloseCb
    cbErr: WsErrorCb
    cbRetry: WsRetryCb
    cbGiveUp: WsGiveUpCb
    # Runtime state
    cur: WsConnection
    attemptsTotal: int      ## Every dial attempt ever made by this client
    consecFails: int        ## Failures since the last successful open
    retryTimer: TimerId
    stopping: bool
    armed: bool              ## A connect() is pending, active or retrying

const DefaultWsReconnectPolicy* = WsReconnectPolicy(
  maxRetries: -1, backoffStartMs: 500, backoffMaxMs: 10_000, jitter: 0.25)

proc newWsClient*(policy: WsReconnectPolicy = DefaultWsReconnectPolicy;
                  maxFrameSize: int = DefaultMaxFrameSize;
                  handshakeTimeoutMs: int = 10_000): WsClient =
  ## Create a WebSocket client that owns its event loop. Call the `on*`
  ## setters, then `connect()`, then `run()`.
  WsClient(
    loop: newLoop(),
    policy: policy,
    rng: initRand(),
    maxFrameSize: maxFrameSize,
    handshakeTimeoutMs: handshakeTimeoutMs,
    retryTimer: TimerId(0),
  )

# ── Callback setters (survive reconnects) ────────────────────────────────────

proc onOpen*(c: WsClient, cb: WsOpenCb) {.inline.} =
  ## Fires for every established session.
  c.cbOpen = cb

proc onMessage*(c: WsClient, cb: WsMessageCb) {.inline.} =
  c.cbMsg = cb

proc onClose*(c: WsClient, cb: WsCloseCb) {.inline.} =
  ## Fires when a session ends, whether or not a reconnect follows.
  c.cbClose = cb

proc onError*(c: WsClient, cb: WsErrorCb) {.inline.} =
  c.cbErr = cb

proc onRetry*(c: WsClient, cb: WsRetryCb) {.inline.} =
  c.cbRetry = cb

proc onGiveUp*(c: WsClient, cb: WsGiveUpCb) {.inline.} =
  c.cbGiveUp = cb

# ── Lifecycle ────────────────────────────────────────────────────────────────

proc attempt(c: WsClient)

proc isConnected*(c: WsClient): bool {.inline.} =
  ## True when the current session completed the handshake and its transport
  ## is still open.
  c.cur != nil and c.cur.isEstablished()

proc session*(c: WsClient): WsConnection {.inline.} =
  ## The current (or most recent) session. Prefer the `ws` argument handed to
  ## callbacks; this accessor exists for code outside them.
  c.cur

proc attemptCount*(c: WsClient): int {.inline.} =
  ## Total dial attempts since construction, including successful ones.
  c.attemptsTotal

proc scheduleRetry(c: WsClient) =
  if c.stopping: return
  inc c.consecFails
  if c.policy.maxRetries >= 0 and c.consecFails > c.policy.maxRetries:
    if not c.cbGiveUp.isNil:
      c.cbGiveUp(c.consecFails)
    c.armed = false
    c.loop.stop()             # release run()
    return
  var base = c.policy.backoffStartMs
  if base <= 0: base = 1
  # Exponential growth, shift capped to avoid overflow.
  let exp = min(c.consecFails - 1, 16)
  base = min(base * (1 shl exp), c.policy.backoffMaxMs)
  let jitter = clamp(c.policy.jitter, 0.0, 0.95)
  var delay = base
  if jitter > 0:
    delay += int(base.float * c.rng.rand(jitter))
  delay = min(delay, c.policy.backoffMaxMs * 2)
  if not c.cbRetry.isNil:
    c.cbRetry(c.consecFails, delay)
  let timer = c.loop.addTimer(max(delay, 1)) do (id: int):
    c.retryTimer = TimerId(0)
    c.attempt()
  c.retryTimer = timer

proc attempt(c: WsClient) =
  if c.stopping: return
  inc c.attemptsTotal
  c.cur = connectWs(c.loop, c.tHost, c.tPort, c.tPath, c.tHost,
    onOpen = proc(ws: WsConnection) =
      c.consecFails = 0
      if not c.cbOpen.isNil: c.cbOpen(ws)
    ,
    onMessage = proc(ws: WsConnection, kind: WsFrameKind,
                     data: openArray[byte]) =
      if not c.cbMsg.isNil: c.cbMsg(ws, kind, data)
    ,
    onClose = proc(ws: WsConnection, code: int, reason: string) =
      if not c.cbClose.isNil: c.cbClose(ws, code, reason)
      if c.stopping: return
      # Only abnormal drops (no close frame received) reconnect; clean closes
      # of any code end the lifecycle.
      if code == 1006:
        c.scheduleRetry()
    ,
    onError = proc(ws: WsConnection, err: string) =
      if not c.cbErr.isNil: c.cbErr(ws, err)
      if c.stopping: return
      # Pre-open failures surface here only. Post-open transport errors also
      # land here (recv failures fire onError without a close frame), so treat
      # an error after a completed handshake as an abnormal drop as well.
      c.scheduleRetry()
    ,
    maxFrameSize = c.maxFrameSize,
    handshakeTimeoutMs = c.handshakeTimeoutMs,
    tlsCtx = c.tlsCtx,
    extraHeaders = c.extraHeaders,
    protocols = c.protocols,
    pingIntervalMs = c.pingIntervalMs,
    idleTimeoutMs = c.idleTimeoutMs,
  )

proc connect*(c: WsClient, url: string;
              headers: openArray[(string, string)] = [];
              protocols: openArray[string] = [];
              pingIntervalMs: int = 0; idleTimeoutMs: int = 0): bool =
  ## Connect to a ws:// or wss:// URL. Raises `WsError` when the URL is
  ## malformed; wss:// targets get a verifying TLS context unless one was
  ## assigned earlier via `setTlsContext`. Returns false when this client is
  ## already connecting or connected; otherwise schedules the first attempt
  ## (it runs once `run()` is entered).
  let parsed = parseWsUrl(url)
  if c.armed:
    return false
  c.tHost = parsed.host
  c.tPort = parsed.port
  c.tPath = parsed.path
  c.extraHeaders = @headers
  c.protocols = @protocols
  c.pingIntervalMs = pingIntervalMs
  c.idleTimeoutMs = idleTimeoutMs
  if parsed.tls and c.tlsCtx == nil:
    c.tlsCtx = newClientTlsContext(verifyPeer = true)
  c.stopping = false
  c.consecFails = 0
  c.armed = true
  discard c.loop.addTimer(1) do (id: int):
    c.attempt()
  result = true

proc connect*(c: WsClient, host: string, port: int, path: string = "/";
              headers: openArray[(string, string)] = [];
              protocols: openArray[string] = [];
              pingIntervalMs: int = 0; idleTimeoutMs: int = 0): bool =
  ## Connect to host:port over plain TCP (use `connect(url)` for wss://).
  if c.armed:
    return false
  c.tHost = host
  c.tPort = port
  c.tPath = path
  c.extraHeaders = @headers
  c.protocols = @protocols
  c.pingIntervalMs = pingIntervalMs
  c.idleTimeoutMs = idleTimeoutMs
  c.stopping = false
  c.consecFails = 0
  c.armed = true
  discard c.loop.addTimer(1) do (id: int):
    c.attempt()
  result = true

proc setTlsContext*(c: WsClient, ctx: SslContext) {.inline.} =
  ## Provide the TLS context used for subsequent wss:// connects (e.g. a
  ## non-verifying one against self-signed servers).
  c.tlsCtx = ctx

proc close*(c: WsClient, code: int = 1000, reason: string = "") =
  ## Deliberate shutdown: tears down the session (if any), cancels pending
  ## retries and stops the internal loop so a blocked `run()` returns.
  ## Deliberate closes never trigger a reconnect. This client cannot be
  ## reused afterwards; create a new one instead.
  if c.stopping: return
  c.stopping = true
  c.armed = false
  if c.retryTimer != TimerId(0):
    c.loop.cancelTimer(c.retryTimer)
    c.retryTimer = TimerId(0)
  if c.cur != nil and c.cur.conn != nil:
    if c.cur.conn.state == Connected:
      c.cur.closeWs(code, reason)
    else:
      c.cur.conn.close()
  c.loop.stop()

proc run*(c: WsClient) =
  ## Drive the client's internal loop on the calling thread. Returns after
  ## `close()` or when the reconnect policy gives up. The loop is closed on
  ## exit; the client is terminal at that point.
  c.loop.run()
  c.loop.close()

proc sendMessage*(c: WsClient, data: string) {.inline.} =
  ## Send a text frame on the current session (no-op while disconnected).
  if isConnected(c):
    c.cur.sendMessage(data)

proc sendMessage*(c: WsClient, data: seq[byte]) {.inline.} =
  ## Send a binary frame on the current session (no-op while disconnected).
  if isConnected(c):
    c.cur.sendMessage(data)
