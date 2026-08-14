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
  IORING_OP_SENDFILE*     = 40

  # sqe.flags bits
  IOSQE_FIXED_FILE* = 0x1   # (1U << 0): treat sqe.fd as a fixed-file table index
  IOSQE_BUFFER_SELECT* = 0x20  # (1U << 5): select buffer from sqe.buf_group

  # sqe.ioprio flags for IORING_OP_RECV (kernel 5.19+)
  IORING_RECV_MULTISHOT* = 2   # (1U << 1): multishot recv, sets IORING_CQE_F_MORE

  # io_uring_register(2) opcodes (linux/io_uring.h)
  IORING_REGISTER_FILES*          = 2
  IORING_UNREGISTER_FILES*        = 3
  IORING_REGISTER_FILES_UPDATE*   = 6

  # cqe.flags bits
  IORING_CQE_F_MORE*   = 0x1   # (1U << 0): this op will generate more completions

  # accept flags (kernel 6.0+)
  IORING_ACCEPT_MULTISHOT* = 0x1

  # fixed-file table size (configurable via -d:powpowFixedFiles=N). Fds at or
  # above this are served by direct (non-fixed) ops.
  FixedFilesTableSize* = when defined(powpowFixedFiles): powpowFixedFiles else: 8192

  IOSQE_IO_LINK* = 4

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

  IoUringFilesUpdate* = object
    ## struct io_uring_files_update — for IORING_REGISTER_FILES_UPDATE.
    offset*: uint32
    resv*:   uint32
    fds*:    uint64   # pointer to the int32 fd array to install

# ── Raw syscalls ─────────────────────────────────────────────────────────────

proc iouSyscall(num, a1, a2, a3, a4, a5, a6: clong): clong {.
  importc: "syscall", header: "<unistd.h>".}

proc setBufGroup*(sqe: ptr IoUringSqe, bgid: uint16) {.inline.} =
  ## Store the buffer group id in the SQE's `buf_index` field (first two bytes
  ## of the pad region) for ops using IOSQE_BUFFER_SELECT.
  cast[ptr uint16](addr sqe.pad[0])[] = bgid

proc ioUringEnter(fd: cint, toSubmit, minComplete, flags: cuint): cint =
  iouSyscall(IoUringEnterNum, fd.clong, toSubmit.clong, minComplete.clong,
             flags.clong, 0, 0).cint

proc ioUringRegister(fd: cint, opcode, arg: clong, nrArgs: cuint): cint =
  iouSyscall(IoUringRegisterNum, fd.clong, opcode, arg, nrArgs.clong, 0, 0).cint

# ── Runtime kernel version (for gated fast paths) ────────────────────────────

proc kernelVersion*(): tuple[major, minor: int] {.gcsafe.} =
  ## (major, minor) of the running Linux kernel; (-1, -1) when unknown.
  result = (-1, -1)
  var buf: array[64, char]
  let fd = posix.open("/proc/sys/kernel/osrelease", O_RDONLY)
  if fd < 0:
    return
  let n = posix.read(fd, addr buf[0], buf.len.cint)
  discard posix.close(fd)
  if n <= 0:
    return
  var s = newString(n)
  copyMem(addr s[0], addr buf[0], n)
  # "6.8.0-45-generic" | "5.15.0-91-generic"
  let parts = s.split('.')
  if parts.len < 2:
    return
  result.major = parts[0].parseInt()
  result.minor = parts[1].parseInt()

proc kernelAtLeast*(major, minor: int): bool {.inline, gcsafe.} =
  ## True when the running kernel is >= `major.minor`. The kernel version is
  ## read once and cached; an unreadable version is treated as "old" (fast
  ## paths stay off).
  var v {.global, noinit.}: tuple[major, minor: int]
  var ok {.global, noinit.}: bool
  if not ok:
    v = kernelVersion()
    ok = true
  v.major > major or (v.major == major and v.minor >= minor)

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
    fixedFilesEnabled: bool   # IORING_REGISTER_FILES succeeded
    fixedFilesSize:    int    # size of the registered table (0 when disabled)
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
    if ring.fixedFilesEnabled:
      discard ioUringRegister(ring.ringFd, IORING_UNREGISTER_FILES, 0, 0)
      ring.fixedFilesEnabled = false
    discard posix.close(ring.ringFd)
    ring.ringFd = -1

# ── Fixed files (IORING_REGISTER_FILES) ───────────────────────────────────────

proc isFixedFd*(ring: Ring, fd: int): bool {.inline.} =
  ## True when `fd` is eligible to be referenced through the fixed-file table
  ## (registration succeeded and the fd number fits the table).
  ring.fixedFilesEnabled and fd >= 0 and fd < ring.fixedFilesSize

proc registerFixedFiles*(ring: Ring, wakeFd: int): bool {.gcsafe.} =
  ## Install a fixed-file table indexed by fd number (`slot[fd] = fd`), sized
  ## `FixedFilesTableSize`. The wake eventfd slot is pre-filled. Returns false
  ## when the kernel rejects registration (older kernel / seccomp) — callers
  ## then keep using direct fds; this is not an error.
  ##
  ## `-d:powpowNoFixedFiles` disables fixed files entirely (direct fds for
  ## every op). Registering/updating the table costs a synchronous
  ## `io_uring_register` syscall per connection (accept + close); the A/B
  ## escape hatch lets the CI benchmark decide whether that cost is worth the
  ## per-op fixed-fd savings.
  when defined(powpowNoFixedFiles):
    ring.fixedFilesEnabled = false
    ring.fixedFilesSize = 0
    return false
  ring.fixedFilesSize = FixedFilesTableSize
  var table = newSeq[int32](FixedFilesTableSize)
  for i in 0 ..< FixedFilesTableSize:
    table[i] = -1
  if wakeFd >= 0 and wakeFd < FixedFilesTableSize:
    table[wakeFd] = wakeFd.cint
  let ret = ioUringRegister(ring.ringFd, IORING_REGISTER_FILES,
                            cast[clong](addr table[0]), FixedFilesTableSize.cuint)
  if ret < 0:
    ring.fixedFilesEnabled = false
    ring.fixedFilesSize = 0
    return false
  ring.fixedFilesEnabled = true
  true

proc updateFixedFile*(ring: Ring, fd: int, value: int32): bool {.gcsafe.} =
  ## Install `value` at slot[fd] (e.g. `fd` when a connection opens, `-1` when
  ## it closes) via IORING_REGISTER_FILES_UPDATE. Synchronous, so the slot is
  ## current before any subsequent op on `fd` is submitted.
  if not ring.isFixedFd(fd):
    return false
  var upd = IoUringFilesUpdate(
    offset: fd.uint32,
    resv:   0,
    fds:    cast[uint64](addr value),
  )
  # IORING_REGISTER_FILES_UPDATE returns the number of fds updated (1), not 0.
  result = ioUringRegister(ring.ringFd, IORING_REGISTER_FILES_UPDATE,
                           cast[clong](addr upd), 1) >= 0

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
  else:
    # A hard io_uring_enter error (EFAULT/EBADF/ENOMEM, i.e. a corrupted SQE or
    # closed ring). Do NOT leave `lastSubmit` behind: resubmitting the identical
    # SQEs on every iteration would spin the loop forever. Advance past them and
    # surface the negative errno so the loop can treat the ring as broken rather
    # than hang.
    ring.lastSubmit = ring.sqTail[]
  ret

# ── Completion ───────────────────────────────────────────────────────────────

proc peekCqe*(ring: Ring): ptr IoUringCqe {.inline, gcsafe.} =
  if ring.cqHead[] != ring.cqTail[]:
    inc ring.reapCount
    result = addr ring.cqes[ring.cqHead[] and ring.cqRingMask[]]

proc advanceCq*(ring: Ring) {.inline, gcsafe.} =
  inc ring.cqHead[]
