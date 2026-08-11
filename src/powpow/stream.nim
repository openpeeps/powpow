# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/stream.nim — Raw-fd streaming for arbitrary file descriptors.
##
## `IoStream` wraps a non-blocking fd and drives it from the powpow event loop:
##
##   let s = openStream(loop, pipeFd,
##     onData  = proc(s: IoStream, data: openArray[byte]) = ...,
##     onClose = proc(s: IoStream) = ...)
##   discard s.write("hello")     # direct write, buffers + flushes on Write
##   s.pause()                    # read backpressure (blocks the pipe writer)
##   s.resume()
##   s.closeAfterWrite()          # flush pending writes then EOF to the peer
##
## This enables pipes, subprocess stdout, socketpair/UDS IPC and (on kqueue)
## regular-file fds. The write path mirrors `Connection`: direct writes are
## drained until EAGAIN and the remainder is buffered with an edge-triggered
## Write watch; reads drain fully per edge-triggered Read event.
##
## `onClose` fires exactly once — from `close`, which is the single terminal
## transition, whether reached by peer EOF, a hard error, or an explicit call.
##
## Platform notes:
## - POSIX only. The Windows IOCP backend can only register sockets, so this
##   module compiles to nothing there (a dedicated pipe path is future work).
## - Regular files: kqueue (macOS/BSD) monitors them fine; epoll rejects
##   regular-file fds (EPERM), so Linux file streaming belongs to the planned
##   thread-pool work.
## - Writes to a closed peer return EPIPE and are treated as a fatal error
##   (powpow ignores SIGPIPE globally), closing the stream.

when not defined(windows):
  import std/posix
  import ./loop, ./types
  import ./net/common, ./net/tcp

  const MaxIoStreamWriteBuffer* = 32 * 1024 * 1024
    ## Per-stream cap on the queued write buffer. A peer that stops reading
    ## must not make us accumulate an unbounded payload (slow-read DoS), the
    ## same guard Connection applies.

  type
    IoStreamState* = enum
      StreamOpen
      StreamClosed

    IoStream* = ref object
      fd*:              int
      loop*:            Loop
      state*:           IoStreamState
      onData:           proc(s: IoStream, data: openArray[byte]) {.closure.}
      onClose*:         proc(s: IoStream) {.closure.}
      readBuf:          ptr UncheckedArray[byte]
      readBufLen:       int
      writeBuf:         seq[byte]
      writePos:         int
      paused:           bool
      closeAfterWrite:  bool
      watch:            set[EventType]   ## last watch set applied to the fd
      data*:            pointer          ## user state, like Connection

  proc handleStreamEvent(s: IoStream, ev: set[EventType])
  proc handleRead(s: IoStream)
  proc close*(s: IoStream)

  proc watchEvents(s: IoStream): set[EventType] {.inline.} =
    ## The watch set the stream needs right now, or {} when nothing should be
    ## watched (paused with an empty write buffer).
    if s.state != StreamOpen:
      return {}
    if s.paused:
      return if s.writeBuf.len > s.writePos: {Write} else: {}
    if s.writeBuf.len > s.writePos:
      return {Read, Write}
    {Read}

  proc rearm(s: IoStream) {.inline.} =
    ## (Re)establish the fd watch set to match the stream's current needs.
    ## Uses modify() for transitions between non-empty sets; unregister/register
    ## only when the stream becomes fully idle (paused, nothing buffered).
    if s.state != StreamOpen: return
    let target = s.watchEvents()
    if target == s.watch: return
    if target == {}:
      s.loop.unregister(s.fd)
    elif s.watch == {}:
      s.loop.register(s.fd, target, edgeTriggered = true,
        callback = proc(fd: int, ev: set[EventType]) =
          s.handleStreamEvent(ev))
    else:
      s.loop.modify(s.fd, target)
    s.watch = target

  proc flushWriteBuffer(s: IoStream): bool =
    ## Drain the queued write buffer until EAGAIN. Returns true when the
    ## buffer is fully flushed (or the stream was closed by a hard write
    ## error); false when it would block (keep the Write watch armed).
    while s.writePos < s.writeBuf.len:
      let n = posix.write(s.fd.cint,
                          unsafeAddr s.writeBuf[s.writePos],
                          s.writeBuf.len - s.writePos)
      if n < 0:
        if sockWouldBlock():
          return false
        s.close()
        return true
      if n == 0:
        return false  # defensive: write() returning 0 with len > 0
      s.writePos += n
    s.writeBuf.setLen(0)
    s.writePos = 0
    true

  proc queueWrite(s: IoStream, data: openArray[byte]): bool =
    ## Append `data` to the write buffer, closing the stream if it would
    ## exceed the cap. Returns true on success.
    if data.len == 0:
      return true
    if s.writeBuf.len + data.len > MaxIoStreamWriteBuffer:
      s.close()
      return false
    let oldLen = s.writeBuf.len
    s.writeBuf.setLen(oldLen + data.len)
    copyMem(addr s.writeBuf[oldLen], unsafeAddr data[0], data.len)
    true

  proc handleStreamEvent(s: IoStream, ev: set[EventType]) =
    if s.state == StreamClosed: return
    if Error in ev:
      s.close()
      return
    if Write in ev:
      if s.flushWriteBuffer():
        if s.state == StreamClosed:
          return
        if s.closeAfterWrite:
          s.close()
          return
        s.rearm()
    if Read in ev or Hup in ev:
      s.handleRead()

  proc handleRead(s: IoStream) =
    ## Drain the fd until EAGAIN/EOF (edge-triggered: must read everything
    ## available per event or no further Read event fires).
    while s.state == StreamOpen and not s.paused:
      let n = posix.read(s.fd.cint, addr s.readBuf[0], s.readBufLen)
      if n > 0:
        s.onData(s, s.readBuf.toOpenArray(0, n - 1))
      elif n == 0:
        s.close()
        return
      else:
        if sockInterrupted():
          continue
        if sockWouldBlock():
          return
        s.close()
        return

  proc openStream*(loop: Loop, fd: int,
                   onData: proc(s: IoStream, data: openArray[byte]) {.closure.},
                   onClose: proc(s: IoStream) {.closure.} = nil): IoStream =
    ## Take ownership of `fd` and drive it from `loop`. The fd is put into
    ## non-blocking mode; `onData` fires per read chunk (edge-triggered
    ## drain), `onClose` fires once when the peer closes (EOF), the fd
    ## errors, or `close` is called.
    setNonBlocking(SocketHandle(fd))
    result = IoStream(
      fd:              fd,
      loop:            loop,
      state:           StreamOpen,
      onData:          onData,
      onClose:         onClose,
      readBuf:         acquireBuf(loop),
      readBufLen:      DefaultBufSize,
      writeBuf:        @[],
      paused:          false,
      closeAfterWrite: false,
      watch:           {},
      data:            nil,
    )
    result.rearm()

  proc close*(s: IoStream) =
    ## Close the stream: unregister, close the fd, return the read buffer,
    ## then fire `onClose` once. Idempotent.
    if s.state == StreamClosed: return
    s.state = StreamClosed
    if s.fd >= 0:
      s.loop.unregister(s.fd)
      discard posix.close(s.fd.cint)
      s.fd = -1
    s.writeBuf.setLen(0)
    s.writePos = 0
    s.watch = {}
    if s.readBuf != nil:
      releaseBuf(s.loop, s.readBuf)
      s.readBuf = nil
    if s.onClose != nil:
      s.onClose(s)

  proc write*(s: IoStream, data: openArray[byte]): int =
    ## Write `data` to the stream. Tries a direct write, draining until
    ## EAGAIN, then buffers the remainder and watches for writability
    ## (edge-triggered Write events only fire on a readiness transition, so
    ## the remainder must never sit buffered while the fd is writable).
    ## Returns `data.len` on acceptance (buffered or fully sent), -1 on a
    ## hard error (the stream is closed; `onClose` fired).
    if s.state != StreamOpen: return 0
    if data.len == 0: return 0

    if s.writeBuf.len > s.writePos:
      if not s.queueWrite(data):
        return 0
      return data.len

    var pos = 0
    while pos < data.len:
      let n = posix.write(s.fd.cint, unsafeAddr data[pos], data.len - pos)
      if n < 0:
        if sockWouldBlock():
          break
        s.close()
        return -1
      if n == 0:
        break  # defensive: write() returning 0 with len > 0
      pos += n

    if pos < data.len:
      let remaining = data.len - pos
      s.writeBuf.setLen(remaining)
      copyMem(addr s.writeBuf[0], unsafeAddr data[pos], remaining)
      s.writePos = 0
      s.rearm()
    return data.len

  proc write*(s: IoStream, data: string): int =
    if data.len == 0: return 0
    s.write(data.toOpenArrayByte(0, data.high))

  proc pause*(s: IoStream) =
    ## Pause reading: no further `onData` deliveries until `resume`. A paused
    ## reader lets the kernel buffer fill, applying backpressure to the writer
    ## (the point of pipes). Pending writes still flush.
    if s.state != StreamOpen or s.paused: return
    s.paused = true
    s.rearm()

  proc resume*(s: IoStream) =
    ## Resume reading after `pause`; any data buffered meanwhile is delivered
    ## immediately.
    if s.state != StreamOpen or not s.paused: return
    s.paused = false
    s.rearm()
    s.handleRead()

  proc closeAfterWrite*(s: IoStream) =
    ## Flush pending writes, then close the fd (delivering EOF to the peer).
    if s.state != StreamOpen: return
    s.closeAfterWrite = true
    if s.writeBuf.len == s.writePos:
      s.close()
    else:
      s.rearm()

  proc newStreamPair*(loop: Loop,
                      onData: proc(s: IoStream, data: openArray[byte]) {.closure.},
                      onClose: proc(s: IoStream) {.closure.} = nil,
                      onData2: proc(s: IoStream, data: openArray[byte]) {.closure.} = nil,
                      onClose2: proc(s: IoStream) {.closure.} = nil): (IoStream, IoStream) =
    ## Create a full-duplex socketpair; both ends are returned as `IoStream`s
    ## on `loop`. Usable as the plumbing for IPC and subprocess stdio.
    var fds: array[2, cint]
    if socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0:
      raise newException(NetError, "socketpair() failed")
    let a = openStream(loop, fds[0].int, onData, onClose)
    let b = openStream(loop, fds[1].int,
                       (if onData2 != nil: onData2 else: onData),
                       (if onClose2 != nil: onClose2 else: onClose))
    (a, b)
