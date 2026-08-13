# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/io/uring.nim — io_uring ring core (Linux).
##
## Raw io_uring bindings and a minimal submission/completion ring helper.
## Uses only the `io_uring_setup`/`io_uring_enter`/`io_uring_register`
## syscalls (no liburing dependency) and one-shot operations, so it works on
## kernels >= 5.6 (multishot/POLL_UPDATE are deliberately avoided).
##
## This is a Linux-only backend. Compiling it on another OS is an error.

when not defined(linux):
  {.error: "powpow/io/uring: io_uring backend requires Linux".}

import std/posix
import std/strutils
import ../types

const
  # syscall numbers (x86_64/arm64)
  IoUringSetupNum   = 425
  IoUringEnterNum   = 426
  IoUringRegisterNum = 427

  # mmap offsets for the three ring regions
  IORING_OFF_SQ_RING = 0
  IORING_OFF_CQ_RING = 0x8000000
  IORING_OFF_SQES    = 0x10000000

  IORING_ENTER_GETEVENTS* = 1

  IORING_SETUP_IOPOLL = 1

  # opcodes (kernel 5.15 io_uring.h)
  IORING_OP_NOP*          = 0
  IORING_OP_POLL_ADD*     = 6
  IORING_OP_POLL_REMOVE*  = 7
  IORING_OP_SENDMSG*      = 9
  IORING_OP_RECVMSG*      = 10
  IORING_OP_TIMEOUT*      = 11
  IORING_OP_ACCEPT*       = 13
  IORING_OP_ASYNC_CANCEL* = 14
  IORING_OP_CONNECT*      = 16
  IORING_OP_READ*         = 22
  IORING_OP_WRITE*        = 23
  IORING_OP_SEND*         = 26
  IORING_OP_RECV*         = 27
  IORING_OP_SPLICE*       = 30
  IORING_OP_PROVIDE_BUFFERS* = 31
  IORING_OP_REMOVE_BUFFERS*  = 32

  IOSQE_IO_LINK* = 4

  # sqe.flags bits
  IOSQE_FIXED_FILE*    = 0x1
  IOSQE_BUFFER_SELECT* = 0x20   # (1U << 5): select buffer from sqe->buf_group

  # send/recv flags carried in sqe.ioprio
  IORING_RECV_MULTISHOT* = 2    # (1U << 1): multishot recv, sets IORING_CQE_F_MORE

  # accept flags carried in sqe.opFlags (accept_flags)
  IORING_ACCEPT_MULTISHOT* = 1  # (1U << 0): multishot accept, sets IORING_CQE_F_MORE

  # cqe.flags bits
  IORING_CQE_F_BUFFER* = 1      # buffer-select completion; buffer id is in the
                                # upper 16 bits of cqe.flags (IORING_CQE_BUFFER_SHIFT)
                                # on modern kernels, res' upper 16 bits on older
  IORING_CQE_F_MORE*   = 2      # parent SQE will produce more CQEs (multishot)

  # poll() masks (linux/poll.h)
  POLLIN*    = 0x1
  POLLOUT*   = 0x4
  POLLERR*   = 0x8
  POLLHUP*   = 0x10
  POLLRDHUP* = 0x2000

  # poll flags carried in the high bits of sqe.poll_events
  IORING_POLL_ADD_MULTI = (1 shl 16)

const
  MAP_POPULATE = 0x8000

# ── Structs (kernel ABI) ─────────────────────────────────────────────────────

type
  IoUringSqe* = object
    opcode*:  uint8
    flags*:   uint8
    ioprio*:  uint16
    fd*:      int32
    off*:     uint64
    paddr*:   uint64
    len*:     uint32
    opFlags*: uint32        # rw_flags / poll_events / accept_flags / ... union
    userData*: uint64
    pad:      array[24, byte]  # buf_index/personality/file_index/__pad3

  IoUringCqe* = object
    userData*: uint64
    res*:      int32
    flags*:    uint32

  IoUringOffsets = object
    head*:       uint32
    tail*:       uint32
    ringMask*:   uint32
    ringEntries*: uint32
    flags*:      uint32
    dropped*:    uint32
    array*:      uint32
    resv1*:      uint32
    userAddr*:   uint64

  IoUringCqOffsets = object
    head*:       uint32
    tail*:       uint32
    ringMask*:   uint32
    ringEntries*: uint32
    overflow*:   uint32
    cqes*:       uint32
    flags*:      uint32
    resv1*:      uint32
    userAddr*:   uint64

  IoUringParams = object
    sqEntries*:  uint32
    cqEntries*:  uint32
    flags*:      uint32
    sqThreadCpu*: uint32
    sqThreadIdle*: uint32
    features*:   uint32
    wqFd*:       uint32
    resv:        array[3, uint32]
    sqOff*:      IoUringOffsets
    cqOff*:      IoUringCqOffsets

  KernelTimespec* = object
    tvSec*:  int64
    tvNsec*: int64

# ── Raw syscalls ─────────────────────────────────────────────────────────────

proc iouSyscall(num, a1, a2, a3, a4, a5, a6: clong): clong {.
  importc: "syscall", header: "<unistd.h>".}

proc ioUringEnter(fd: cint, toSubmit, minComplete, flags: cuint): cint =
  iouSyscall(IoUringEnterNum, fd.clong, toSubmit.clong, minComplete.clong,
             flags.clong, 0, 0).cint

proc setBufGroup*(sqe: ptr IoUringSqe, bgid: uint16) {.inline.} =
  ## Store the buffer group id in the SQE's `buf_index` field (first two bytes
  ## of the pad region) for ops using IOSQE_BUFFER_SELECT.
  cast[ptr uint16](addr sqe.pad[0])[] = bgid

proc kernelAtLeast*(major, minor: int): bool {.gcsafe.} =
  ## Feature check against the running kernel (for ops like multishot recv that
  ## are version-gated rather than exposed via `IoUringParams.features`).
  try:
    let v = readFile("/proc/sys/kernel/osrelease").split('.')
    if v.len >= 2:
      result = parseInt(v[0]) > major or
               (parseInt(v[0]) == major and parseInt(v[1]) >= minor)
  except CatchableError:
    result = false

# ── Ring ─────────────────────────────────────────────────────────────────────

type
  Ring* = ref object
    ringFd*:        cint
    entries*:       int
    sqHead*:        ptr uint32
    sqTail*:        ptr uint32
    sqRingMask*:    ptr uint32
    sqRingEntries*: ptr uint32
    sqArray*:       ptr UncheckedArray[uint32]
    cqHead*:        ptr uint32
    cqTail*:        ptr uint32
    cqRingMask*:    ptr uint32
    cqRingEntries*: ptr uint32
    cqOverflow*:    ptr uint32
    cqes*:          ptr UncheckedArray[IoUringCqe]
    sqes*:          ptr UncheckedArray[IoUringSqe]
    lastSubmit:     uint32
    maps:           seq[(pointer, int)]
    enterCount*:    int
    submitCount*:   int
    reapCount*:     int

proc raiseFd(fd: var cint) {.inline.} =
  ## Keep control fds out of the 0..2 range (see kqueue backend).
  if fd >= 0 and fd < 3:
    let nf = fcntl(fd, F_DUPFD, 3)
    if nf >= 0:
      discard posix.close(fd)
      fd = nf

proc initRing*(entries: int = 4096): Ring {.gcsafe.} =
  result = Ring(entries: entries)
  var params: IoUringParams
  zeroMem(addr params, sizeof(params))
  let fd = iouSyscall(IoUringSetupNum, entries.clong, cast[clong](addr params),
                      0, 0, 0, 0)
  if fd < 0:
    let e = errno
    if e == ENOSYS:
      raise newException(OSError,
        "powpow io_uring: io_uring_setup returned ENOSYS (kernel < 5.6 or " &
        "io_uring disabled). Use the epoll backend or a newer kernel.")
    raise newException(OSError,
      "powpow io_uring: io_uring_setup failed (errno " & $e & "); the kernel " &
      "may block io_uring (seccomp/container). Use the epoll backend.")
  result.ringFd = fd.cint
  result.ringFd.raiseFd()

  let sqBytes = params.sqOff.array.int + params.sqEntries.int * 4
  let cqBytes = params.cqOff.cqes.int + params.cqEntries.int * sizeof(IoUringCqe)
  let sqeBytes = params.sqEntries.int * sizeof(IoUringSqe)

  let sq = mmap(nil, sqBytes, PROT_READ or PROT_WRITE,
                MAP_SHARED or MAP_POPULATE, result.ringFd, IORING_OFF_SQ_RING.Off)
  if sq == MAP_FAILED:
    raise newException(OSError, "powpow io_uring: mmap(SQ ring) failed")
  result.maps.add((sq, sqBytes))
  let cq = mmap(nil, cqBytes, PROT_READ or PROT_WRITE,
                MAP_SHARED or MAP_POPULATE, result.ringFd, IORING_OFF_CQ_RING.Off)
  if cq == MAP_FAILED:
    raise newException(OSError, "powpow io_uring: mmap(CQ ring) failed")
  result.maps.add((cq, cqBytes))
  let sqes = mmap(nil, sqeBytes, PROT_READ or PROT_WRITE,
                  MAP_SHARED or MAP_POPULATE, result.ringFd, IORING_OFF_SQES.Off)
  if sqes == MAP_FAILED:
    raise newException(OSError, "powpow io_uring: mmap(SQEs) failed")
  result.maps.add((sqes, sqeBytes))

  let sqBase = cast[int](sq)
  let cqBase = cast[int](cq)
  result.sqHead = cast[ptr uint32](sqBase + params.sqOff.head.int)
  result.sqTail = cast[ptr uint32](sqBase + params.sqOff.tail.int)
  result.sqRingMask = cast[ptr uint32](sqBase + params.sqOff.ringMask.int)
  result.sqRingEntries = cast[ptr uint32](sqBase + params.sqOff.ringEntries.int)
  result.sqArray = cast[ptr UncheckedArray[uint32]](sqBase + params.sqOff.array.int)
  result.cqHead = cast[ptr uint32](cqBase + params.cqOff.head.int)
  result.cqTail = cast[ptr uint32](cqBase + params.cqOff.tail.int)
  result.cqRingMask = cast[ptr uint32](cqBase + params.cqOff.ringMask.int)
  result.cqRingEntries = cast[ptr uint32](cqBase + params.cqOff.ringEntries.int)
  result.cqOverflow = cast[ptr uint32](cqBase + params.cqOff.overflow.int)
  result.cqes = cast[ptr UncheckedArray[IoUringCqe]](cqBase + params.cqOff.cqes.int)
  result.sqes = cast[ptr UncheckedArray[IoUringSqe]](sqes)
  result.entries = params.sqEntries.int

proc close*(ring: Ring) {.gcsafe.} =
  for (p, len) in ring.maps:
    discard munmap(p, len)
  ring.maps.setLen(0)
  if ring.ringFd >= 0:
    discard posix.close(ring.ringFd)
    ring.ringFd = -1

# ── Submission ───────────────────────────────────────────────────────────────

proc getSqe*(ring: Ring): ptr IoUringSqe {.inline, gcsafe.} =
  ## Claim one SQE slot. Returns nil when the SQ ring is full (callers should
  ## retry after `io_uring_enter` frees slots).
  if ring.sqTail[] - ring.lastSubmit >= ring.entries.uint32:
    return nil
  let idx = (ring.sqTail[] and ring.sqRingMask[]).int
  result = addr ring.sqes[idx]
  zeroMem(result, sizeof(IoUringSqe))
  ring.sqArray[idx] = idx.uint32
  inc ring.sqTail[]

proc submit*(ring: Ring, minComplete: cuint = 0,
             flags: cuint = 0): cint {.discardable.} =
  ## Submit all pending SQEs. With `minComplete > 0` and IORING_ENTER_GETEVENTS
  ## this blocks until at least one completion (or EINTR).
  let toSubmit = ring.sqTail[] - ring.lastSubmit
  if toSubmit == 0 and minComplete == 0:
    return 0
  inc ring.enterCount
  ring.submitCount += toSubmit.int
  var ret = ioUringEnter(ring.ringFd, toSubmit, minComplete, flags)
  if ret < 0 and errno == EINTR:
    # Submitted SQEs are consumed even when interrupted.
    ring.lastSubmit = ring.sqTail[]
    return -EINTR
  if ret >= 0:
    ring.lastSubmit = ring.sqTail[]
  ret

# ── Completion ───────────────────────────────────────────────────────────────

proc peekCqe*(ring: Ring): ptr IoUringCqe {.inline, gcsafe.} =
  if ring.cqHead[] != ring.cqTail[]:
    inc ring.reapCount
    result = addr ring.cqes[ring.cqHead[] and ring.cqRingMask[]]

proc advanceCq*(ring: Ring) {.inline, gcsafe.} =
  inc ring.cqHead[]
