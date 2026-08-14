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

  # Opcodes — verified against the kernel's `enum io_uring_op` (linux/io_uring.h).
  # Note: io_uring has NO IORING_OP_SENDFILE; the value 40 is IORING_OP_MSG_RING.
  # File→socket transfers use IORING_OP_SPLICE (file→pipe→socket) or a READ +
  # SEND pump, never a nonexistent opcode.
  IORING_OP_NOP*          = 0
  IORING_OP_READV*        = 1
  IORING_OP_WRITEV*       = 2
  IORING_OP_FSYNC*        = 3
  IORING_OP_READ_FIXED*   = 4
  IORING_OP_WRITE_FIXED*  = 5
  IORING_OP_POLL_ADD*     = 6
  IORING_OP_POLL_REMOVE*  = 7
  IORING_OP_SYNC_FILE_RANGE* = 8
  IORING_OP_SENDMSG*      = 9
  IORING_OP_RECVMSG*      = 10
  IORING_OP_TIMEOUT*      = 11
  IORING_OP_TIMEOUT_REMOVE* = 12
  IORING_OP_ACCEPT*       = 13
  IORING_OP_ASYNC_CANCEL* = 14
  IORING_OP_LINK_TIMEOUT* = 15
  IORING_OP_CONNECT*      = 16
  IORING_OP_FALLOCATE*    = 17
  IORING_OP_OPENAT*       = 18
  IORING_OP_CLOSE*        = 19
  IORING_OP_FILES_UPDATE* = 20
  IORING_OP_STATX*        = 21
  IORING_OP_READ*         = 22
  IORING_OP_WRITE*        = 23
  IORING_OP_FADVISE*      = 24
  IORING_OP_MADVISE*      = 25
  IORING_OP_SEND*         = 26
  IORING_OP_RECV*         = 27
  IORING_OP_OPENAT2*      = 28
  IORING_OP_EPOLL_CTL*    = 29
  IORING_OP_SPLICE*       = 30
  IORING_OP_PROVIDE_BUFFERS* = 31
  IORING_OP_REMOVE_BUFFERS* = 32
  IORING_OP_TEE*          = 33
  IORING_OP_SHUTDOWN*     = 34
  IORING_OP_RENAMEAT*     = 35
  IORING_OP_UNLINKAT*     = 36
  IORING_OP_MKDIRAT*      = 37
  IORING_OP_SYMLINKAT*    = 38
  IORING_OP_LINKAT*       = 39
  IORING_OP_MSG_RING*     = 40
  IORING_OP_FSETXATTR*    = 41
  IORING_OP_SETXATTR*     = 42
  IORING_OP_FGETXATTR*    = 43
  IORING_OP_GETXATTR*     = 44
  IORING_OP_SOCKET*       = 45
  IORING_OP_URING_CMD*    = 46
  IORING_OP_SEND_ZC*      = 47
  IORING_OP_SENDMSG_ZC*   = 48
  IORING_OP_READ_MULTISHOT* = 49
  IORING_OP_WAITID*       = 50
  IORING_OP_FUTEX_WAIT*   = 51
  IORING_OP_FUTEX_WAKE*   = 52
  IORING_OP_FUTEX_WAITV*  = 53
  IORING_OP_FIXED_FD_INSTALL* = 54

  # sqe.flags bits (IOSQE_*)
  IOSQE_FIXED_FILE* = 0x1        # (1U << 0): treat sqe.fd as a fixed-file table index
  IOSQE_IO_DRAIN* = 0x2          # (1U << 1): wait for preceding requests before this one
  IOSQE_IO_LINK* = 4             # (1U << 2): link with the next request
  IOSQE_IO_HARDLINK* = 0x8       # (1U << 3): hard link (link survives errors)
  IOSQE_ASYNC* = 0x10            # (1U << 4): force async context for the request
  IOSQE_BUFFER_SELECT* = 0x20    # (1U << 5): select buffer from sqe.buf_group
  IOSQE_CQE_SKIP_SUCCESS* = 0x40 # (1U << 6): skip CQE for successful requests

  # sqe.ioprio flags for IORING_OP_RECV (kernel 5.19+)
  IORING_RECV_MULTISHOT* = 2   # (1U << 1): multishot recv, sets IORING_CQE_F_MORE

  # io_uring_register(2) opcodes (linux/io_uring.h)
  IORING_REGISTER_BUFFERS*        = 0
  IORING_REGISTER_FILES*          = 2
  IORING_UNREGISTER_BUFFERS*      = 1
  IORING_UNREGISTER_FILES*        = 3
  IORING_REGISTER_EVENTFD*        = 4
  IORING_REGISTER_FILES_UPDATE*   = 6
  IORING_REGISTER_EVENTFD_ASYNC*  = 7
  IORING_REGISTER_PROBE*          = 8
  IORING_REGISTER_PERSONALITY*    = 9
  IORING_REGISTER_RESTRICTIONS*   = 11
  IORING_REGISTER_ENABLE_RINGS*   = 12
  IORING_REGISTER_FILES2*         = 13
  IORING_REGISTER_FILES_UPDATE2*  = 14
  IORING_REGISTER_BUFFERS2*       = 15
  IORING_REGISTER_BUFFERS_UPDATE* = 16
  IORING_REGISTER_IOWQ_AFF*       = 17
  IORING_REGISTER_IOWQ_MAX_WORKERS* = 19
  IORING_REGISTER_RING_FDS*       = 20
  IORING_REGISTER_PBUF_RING*      = 22
  IORING_REGISTER_SYNC_CANCEL*    = 24
  IORING_REGISTER_FILE_ALLOC_RANGE* = 25
  IORING_REGISTER_PBUF_STATUS*    = 26

  # cqe.flags bits (verified against linux/io_uring.h)
  IORING_CQE_F_BUFFER*       = 0x1  # (1U << 0): upper 16 bits of res are the buffer id
  IORING_CQE_F_MORE*         = 0x2  # (1U << 1): this op will generate more completions
  IORING_CQE_F_SOCK_NONEMPTY* = 0x4 # (1U << 2): more data to read after a socket recv
  IORING_CQE_F_NOTIF*        = 0x8  # (1U << 3): zero-copy notification CQE (send_zc)

  # accept flags (kernel 6.0+)
  IORING_ACCEPT_MULTISHOT* = 0x1

  # IORING_OP_SEND_ZC zero-copy flags (kernel 6.0+)
  IORING_SEND_ZC_REPORT_USAGE* = 0x8  # (1U << 3): report copied bytes in the NOTIF cqe

  # IORING_OP_SPLICE flags
  SPLICE_F_FD_IN_FIXED* = 0x80000000'u32  # in_fd is a fixed-file table index

  # io_uring features (params.features / IORING_FEAT_*)
  IORING_FEAT_SINGLE_MMAP*      = 1'u32 shl 0
  IORING_FEAT_NODROP*           = 1'u32 shl 1
  IORING_FEAT_SUBMIT_STABLE*    = 1'u32 shl 2
  IORING_FEAT_RW_CUR_POS*       = 1'u32 shl 3
  IORING_FEAT_CUR_PERSONALITY*  = 1'u32 shl 4
  IORING_FEAT_FAST_POLL*        = 1'u32 shl 5
  IORING_FEAT_POLL_32BITS*      = 1'u32 shl 6
  IORING_FEAT_SQPOLL_NONFIXED*  = 1'u32 shl 7
  IORING_FEAT_EXT_ARG*          = 1'u32 shl 8
  IORING_FEAT_NATIVE_WORKERS*   = 1'u32 shl 9
  IORING_FEAT_RSRC_TAGS*        = 1'u32 shl 10
  IORING_FEAT_CQE_SKIP*         = 1'u32 shl 11
  IORING_FEAT_LINKED_FILE*      = 1'u32 shl 12
  IORING_FEAT_REG_REG_RING*     = 1'u32 shl 13

  # fixed-file table size (configurable via -d:powpowFixedFiles=N). Fds at or
  # above this are served by direct (non-fixed) ops.
  FixedFilesTableSize* = when defined(powpowFixedFiles): powpowFixedFiles else: 8192

  # poll() masks (linux/poll.h)
  POLLIN*    = 0x1
  POLLOUT*   = 0x4
  POLLERR*   = 0x8
  POLLHUP*   = 0x10
  POLLRDHUP* = 0x2000

  # POLL_ADD command flags. Since kernel 5.16 the poll mask lives in
  # sqe.poll32_events and POLL_ADD command flags are stored in sqe.len.
  IORING_POLL_ADD_MULTI = 1   # (1U << 0): multishot poll (flag space = sqe.len)

  # io_uring_setup(2) flags (params.flags / IORING_SETUP_*)
  IORING_SETUP_IOPOLL*        = 1'u32 shl 0
  IORING_SETUP_SQPOLL*        = 1'u32 shl 1
  IORING_SETUP_SQ_AFF*        = 1'u32 shl 2
  IORING_SETUP_CQSIZE*        = 1'u32 shl 3
  IORING_SETUP_CLAMP*         = 1'u32 shl 4
  IORING_SETUP_ATTACH_WQ*     = 1'u32 shl 5
  IORING_SETUP_R_DISABLED*    = 1'u32 shl 6
  IORING_SETUP_SUBMIT_ALL*    = 1'u32 shl 7
  IORING_SETUP_COOP_TASKRUN*  = 1'u32 shl 8
  IORING_SETUP_TASKRUN_FLAG*  = 1'u32 shl 9
  IORING_SETUP_SQE128*        = 1'u32 shl 10
  IORING_SETUP_CQE32*         = 1'u32 shl 11
  IORING_SETUP_SINGLE_ISSUER* = 1'u32 shl 12
  IORING_SETUP_DEFER_TASKRUN* = 1'u32 shl 13
  IORING_SETUP_NO_MMAP*       = 1'u32 shl 14
  IORING_SETUP_REGISTERED_FD_ONLY* = 1'u32 shl 15
  IORING_SETUP_NO_SQARRAY*    = 1'u32 shl 16

  # io_uring_enter(2) flags (IORING_ENTER_*)
  IORING_ENTER_GETEVENTS*      = 1'u32 shl 0
  IORING_ENTER_SQ_WAKEUP*      = 1'u32 shl 1
  IORING_ENTER_SQ_WAIT*        = 1'u32 shl 2
  IORING_ENTER_EXT_ARG*        = 1'u32 shl 3
  IORING_ENTER_REGISTERED_RING* = 1'u32 shl 4

  # IORING_OP_ASYNC_CANCEL flags (sqe.cancel_flags)
  IORING_ASYNC_CANCEL_ALL* = 1'u32 shl 0   # cancel all matching requests
  IORING_ASYNC_CANCEL_FD*  = 1'u32 shl 1   # sqe.fd is the target fd, not sqe.addr
  IORING_ASYNC_CANCEL_ANY* = 1'u32 shl 2   # match any opcode
  IORING_ASYNC_CANCEL_FD_FIXED* = 1'u32 shl 3  # sqe.fd is a fixed-file index

  # IORING_OP_SHUTDOWN flags (sqe.rw_flags)
  IORING_SHUTDOWN_SEND* = 1   # SHUT_WR
  IORING_SHUTDOWN_RECV* = 2   # SHUT_RD

  # IORING_OP_MSG_RING flags (sqe.msg_ring_flags)
  IORING_MSG_RING_FLAGS_PASS* = 1'u32 shl 0  # pass user_data through to the NOP

  # IORING_OP_SOCKET flags (sqe.rw_flags)
  IORING_SOCKET_DIRECT* = 1'u32 shl 0  # install into the fixed-file table

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

  IoUringProbeOp* = object
    ## struct io_uring_probe_op — one probed opcode.
    op*:    uint8
    resv*:  uint8
    flags*: uint16
    resv2*: uint32

  IoUringProbe* = object
    ## struct io_uring_probe — header of the probe buffer; `ops[]` follows.
    lastOp*: uint8
    opsLen*: uint8
    resv*:   uint16
    resv2*:  array[3, uint32]

  IoUringRsrcRegister* = object
    ## struct io_uring_rsrc_register — IORING_REGISTER_FILES2/BUFFERS2.
    nr*:    uint32
    flags*: uint32
    resv2*: uint64
    data*:  uint64   # pointer to the fd/buf iovec array
    tags*:  uint64

  IoUringRsrcUpdate* = object
    ## struct io_uring_rsrc_update — IORING_REGISTER_FILES_UPDATE (non-SQE).
    offset*: uint32
    resv*:   uint32
    data*:   uint64

  IoUringRsrcUpdate2* = object
    ## struct io_uring_rsrc_update2 — IORING_REGISTER_FILES_UPDATE2.
    offset*: uint32
    resv*:   uint32
    data*:   uint64
    tags*:   uint64
    nr*:     uint32
    resv2*:  uint32

  IoUringBuf* = object
    ## struct io_uring_buf — one entry of a provided-buffer ring.
    bufAddr*: uint64
    len*:  uint32
    bid*:  uint16
    resv*: uint16

  IoUringBufReg* = object
    ## struct io_uring_buf_reg — IORING_(UN)REGISTER_PBUF_RING.
    ringAddr*:   uint64
    ringEntries*: uint32
    bgid*:       uint16
    flags*:      uint16
    resv*:       array[3, uint64]

  IoUringBufStatus* = object
    ## struct io_uring_buf_status — IORING_REGISTER_PBUF_STATUS.
    bufGroup*: uint32
    head*:     uint32
    resv*:     array[8, uint32]

  IoUringGeteventsArg* = object
    ## struct io_uring_getevents_arg — for IORING_ENTER_EXT_ARG.
    sigmask*:   uint64
    sigmaskSz*: uint32
    pad*:       uint32
    ts*:        uint64   # pointer to a struct __kernel_timespec (or NULL)

  IoUringSyncCancelReg* = object
    ## struct io_uring_sync_cancel_reg — for IORING_REGISTER_SYNC_CANCEL.
    bufAddr*:    uint64
    fd*:      int32
    flags*:   uint32
    timeout*: KernelTimespec
    opcode*:  uint8
    pad*:     array[7, uint8]
    pad2*:    array[3, uint64]

# ── Raw syscalls ─────────────────────────────────────────────────────────────

proc iouSyscall(num, a1, a2, a3, a4, a5, a6: clong): clong {.
  importc: "syscall", header: "<unistd.h>".}

proc setBufGroup*(sqe: ptr IoUringSqe, bgid: uint16) {.inline.} =
  ## Store the buffer group id in the SQE's `buf_index` field (first two bytes
  ## of the pad region) for ops using IOSQE_BUFFER_SELECT.
  cast[ptr uint16](addr sqe.pad[0])[] = bgid

proc setBufIndex*(sqe: ptr IoUringSqe, idx: uint16) {.inline.} =
  ## Store a fixed-buffer index (buf_index field, first two bytes of pad) for
  ## IORING_OP_READ_FIXED / WRITE_FIXED / SEND_ZC_FIXED.
  cast[ptr uint16](addr sqe.pad[0])[] = idx

proc setSpliceFdIn*(sqe: ptr IoUringSqe, fdIn: int32) {.inline.} =
  ## Store the splice input fd (splice_fd_in field, bytes 4..7 of pad). The
  ## `off` field carries off_out; `paddr` carries splice_off_in (off_in).
  cast[ptr int32](addr sqe.pad[4])[] = fdIn

proc setFileIndex*(sqe: ptr IoUringSqe, idx: uint32) {.inline.} =
  ## Store the fixed-file index (file_index field, bytes 4..7 of pad) used by
  ## IORING_OP_FILES_UPDATE and ops that install direct descriptors.
  cast[ptr uint32](addr sqe.pad[4])[] = idx

proc setPersonality*(sqe: ptr IoUringSqe, personality: uint16) {.inline.} =
  ## Store the personality id (bytes 2..3 of pad).
  cast[ptr uint16](addr sqe.pad[2])[] = personality

# ── io_uring_prep_* equivalents ───────────────────────────────────────────────
# These mirror the liburing `io_uring_prep_*` helpers so callers never poke raw
# SQE fields. All take an already-claimed SQE slot.

proc prepNop*(sqe: ptr IoUringSqe) {.inline.} =
  sqe.opcode = IORING_OP_NOP.uint8

proc prepRead*(sqe: ptr IoUringSqe, fd: int, buf: pointer, len: int, off: int64) {.inline.} =
  sqe.opcode = IORING_OP_READ.uint8
  sqe.fd = fd.int32
  sqe.paddr = cast[uint64](buf)
  sqe.len = len.uint32
  sqe.off = off.uint64

proc prepWrite*(sqe: ptr IoUringSqe, fd: int, buf: pointer, len: int, off: int64) {.inline.} =
  sqe.opcode = IORING_OP_WRITE.uint8
  sqe.fd = fd.int32
  sqe.paddr = cast[uint64](buf)
  sqe.len = len.uint32
  sqe.off = off.uint64

proc prepReadFixed*(sqe: ptr IoUringSqe, fd: int, buf: pointer, len: int, off: int64, bufIndex: uint16) {.inline.} =
  sqe.opcode = IORING_OP_READ_FIXED.uint8
  sqe.fd = fd.int32
  sqe.paddr = cast[uint64](buf)
  sqe.len = len.uint32
  sqe.off = off.uint64
  sqe.setBufIndex(bufIndex)

proc prepWriteFixed*(sqe: ptr IoUringSqe, fd: int, buf: pointer, len: int, off: int64, bufIndex: uint16) {.inline.} =
  sqe.opcode = IORING_OP_WRITE_FIXED.uint8
  sqe.fd = fd.int32
  sqe.paddr = cast[uint64](buf)
  sqe.len = len.uint32
  sqe.off = off.uint64
  sqe.setBufIndex(bufIndex)

proc prepSend*(sqe: ptr IoUringSqe, fd: int, buf: pointer, len: int, flags: uint32) {.inline.} =
  sqe.opcode = IORING_OP_SEND.uint8
  sqe.fd = fd.int32
  sqe.paddr = cast[uint64](buf)
  sqe.len = len.uint32
  sqe.opFlags = flags

proc prepSendZc*(sqe: ptr IoUringSqe, fd: int, buf: pointer, len: int, flags: uint32, zcFlags: uint32) {.inline.} =
  ## Prepare IORING_OP_SEND_ZC. `addr2` (the off field) carries zc_flags.
  sqe.opcode = IORING_OP_SEND_ZC.uint8
  sqe.fd = fd.int32
  sqe.paddr = cast[uint64](buf)
  sqe.len = len.uint32
  sqe.opFlags = flags
  sqe.off = zcFlags.uint64

proc prepSendZcFixed*(sqe: ptr IoUringSqe, fd: int, buf: pointer, len: int, flags: uint32, zcFlags: uint32, bufIndex: uint16) {.inline.} =
  sqe.prepSendZc(fd, buf, len, flags, zcFlags)
  sqe.setBufIndex(bufIndex)

proc prepSendmsg*(sqe: ptr IoUringSqe, fd: int, msg: pointer, flags: uint32) {.inline.} =
  sqe.opcode = IORING_OP_SENDMSG.uint8
  sqe.fd = fd.int32
  sqe.paddr = cast[uint64](msg)
  sqe.opFlags = flags

proc prepSendmsgZc*(sqe: ptr IoUringSqe, fd: int, msg: pointer, flags: uint32, zcFlags: uint32) {.inline.} =
  sqe.opcode = IORING_OP_SENDMSG_ZC.uint8
  sqe.fd = fd.int32
  sqe.paddr = cast[uint64](msg)
  sqe.opFlags = flags
  sqe.off = zcFlags.uint64

proc prepRecv*(sqe: ptr IoUringSqe, fd: int, buf: pointer, len: int, flags: uint32) {.inline.} =
  sqe.opcode = IORING_OP_RECV.uint8
  sqe.fd = fd.int32
  sqe.paddr = cast[uint64](buf)
  sqe.len = len.uint32
  sqe.opFlags = flags

proc prepRecvMultishot*(sqe: ptr IoUringSqe, fd: int, buf: pointer, len: int, flags: uint32) {.inline.} =
  ## One SQE stays armed and delivers every read as a completion with
  ## IORING_CQE_F_MORE (kernel >= 5.19; use with IOSQE_BUFFER_SELECT).
  sqe.prepRecv(fd, buf, len, flags)
  sqe.ioprio = IORING_RECV_MULTISHOT.uint16

proc prepRecvmsg*(sqe: ptr IoUringSqe, fd: int, msg: pointer, flags: uint32) {.inline.} =
  sqe.opcode = IORING_OP_RECVMSG.uint8
  sqe.fd = fd.int32
  sqe.paddr = cast[uint64](msg)
  sqe.opFlags = flags

proc prepAccept*(sqe: ptr IoUringSqe, fd: int, sa: pointer, addrLen: ptr SockLen, flags: uint32) {.inline.} =
  sqe.opcode = IORING_OP_ACCEPT.uint8
  sqe.fd = fd.int32
  sqe.paddr = cast[uint64](sa)
  sqe.off = cast[uint64](addrLen)
  sqe.opFlags = flags

proc prepAcceptMultishot*(sqe: ptr IoUringSqe, fd: int, flags: uint32) {.inline.} =
  ## addr/addrlen must be NULL for multishot accept; the client address is read
  ## via getpeername in the completion handler.
  sqe.opcode = IORING_OP_ACCEPT.uint8
  sqe.fd = fd.int32
  sqe.opFlags = flags or IORING_ACCEPT_MULTISHOT

proc prepConnect*(sqe: ptr IoUringSqe, fd: int, sa: pointer, addrLen: int) {.inline.} =
  sqe.opcode = IORING_OP_CONNECT.uint8
  sqe.fd = fd.int32
  sqe.paddr = cast[uint64](sa)
  sqe.off = addrLen.uint64

proc prepTimeout*(sqe: ptr IoUringSqe, ts: ptr KernelTimespec, count: uint32, flags: uint32) {.inline.} =
  sqe.opcode = IORING_OP_TIMEOUT.uint8
  sqe.paddr = cast[uint64](ts)
  sqe.len = count
  sqe.opFlags = flags

proc prepTimeoutRemove*(sqe: ptr IoUringSqe, userData: uint64, flags: uint32) {.inline.} =
  sqe.opcode = IORING_OP_TIMEOUT_REMOVE.uint8
  sqe.paddr = userData
  sqe.opFlags = flags

proc prepLinkTimeout*(sqe: ptr IoUringSqe, ts: ptr KernelTimespec, count: uint32, flags: uint32) {.inline.} =
  sqe.opcode = IORING_OP_LINK_TIMEOUT.uint8
  sqe.paddr = cast[uint64](ts)
  sqe.len = count
  sqe.opFlags = flags

proc prepCancel*(sqe: ptr IoUringSqe, userData: uint64, flags: uint32) {.inline.} =
  sqe.opcode = IORING_OP_ASYNC_CANCEL.uint8
  sqe.paddr = userData
  sqe.opFlags = flags

proc prepCancelFd*(sqe: ptr IoUringSqe, fd: int, flags: uint32) {.inline.} =
  ## Cancel by fd instead of by user_data (needs IORING_ASYNC_CANCEL_FD).
  sqe.opcode = IORING_OP_ASYNC_CANCEL.uint8
  sqe.fd = fd.int32
  sqe.opFlags = flags or IORING_ASYNC_CANCEL_FD

proc prepShutdown*(sqe: ptr IoUringSqe, fd: int, how: uint32) {.inline.} =
  sqe.opcode = IORING_OP_SHUTDOWN.uint8
  sqe.fd = fd.int32
  sqe.opFlags = how

proc prepSplice*(sqe: ptr IoUringSqe, fdIn: int, offIn: int64, fdOut: int, offOut: int64, nbytes: int, flags: uint32) {.inline.} =
  ## Zero-copy splice. One end must be a pipe. `fd` carries fd_out, `off` the
  ## output offset, `paddr` the input offset, `splice_fd_in` the input fd.
  sqe.opcode = IORING_OP_SPLICE.uint8
  sqe.fd = fdOut.int32
  sqe.off = offOut.uint64
  sqe.paddr = offIn.uint64
  sqe.len = nbytes.uint32
  sqe.setSpliceFdIn(fdIn.int32)
  sqe.opFlags = flags

proc prepTee*(sqe: ptr IoUringSqe, fdIn: int, fdOut: int, nbytes: int, flags: uint32) {.inline.} =
  sqe.opcode = IORING_OP_TEE.uint8
  sqe.fd = fdOut.int32
  sqe.setSpliceFdIn(fdIn.int32)
  sqe.len = nbytes.uint32
  sqe.opFlags = flags

proc prepProvideBuffers*(sqe: ptr IoUringSqe, bufAddr: pointer, nbufs: int, bufLen: int, bgid: uint16) {.inline.} =
  sqe.opcode = IORING_OP_PROVIDE_BUFFERS.uint8
  sqe.fd = nbufs.int32
  sqe.paddr = cast[uint64](bufAddr)
  sqe.len = bufLen.uint32
  sqe.setBufGroup(bgid)

proc prepRemoveBuffers*(sqe: ptr IoUringSqe, count: int, bgid: uint16) {.inline.} =
  sqe.opcode = IORING_OP_REMOVE_BUFFERS.uint8
  sqe.fd = count.int32
  sqe.setBufGroup(bgid)

proc prepFilesUpdate*(sqe: ptr IoUringSqe, offset: int, fds: ptr int32, nr: int) {.inline.} =
  ## SQE-based fixed-file table update (kernel >= 5.19). Asynchronous: the
  ## completion reports the number of slots updated.
  sqe.opcode = IORING_OP_FILES_UPDATE.uint8
  sqe.fd = offset.int32
  sqe.paddr = cast[uint64](fds)
  sqe.len = nr.uint32

proc prepMsgRing*(sqe: ptr IoUringSqe, ringFd: int, len: uint32, flags: uint32, userData: uint64) {.inline.} =
  sqe.opcode = IORING_OP_MSG_RING.uint8
  sqe.fd = ringFd.int32
  sqe.len = len
  sqe.opFlags = flags
  sqe.paddr = userData

proc prepClose*(sqe: ptr IoUringSqe, fd: int) {.inline.} =
  sqe.opcode = IORING_OP_CLOSE.uint8
  sqe.fd = fd.int32

proc prepSocket*(sqe: ptr IoUringSqe, domain: int, typ: int, protocol: int, flags: uint32) {.inline.} =
  sqe.opcode = IORING_OP_SOCKET.uint8
  sqe.fd = domain.int32
  sqe.opFlags = flags
  sqe.paddr = (typ.uint32 shl 32) or protocol.uint32

proc prepPollAdd*(sqe: ptr IoUringSqe, fd: int, pollMask: uint32, addFlags: uint32) {.inline.} =
  ## One-shot (or multishot with IORING_POLL_ADD_MULTI) poll. Since kernel 5.16
  ## the poll mask lives in poll32_events and POLL_ADD flags in sqe.len.
  sqe.opcode = IORING_OP_POLL_ADD.uint8
  sqe.fd = fd.int32
  sqe.opFlags = pollMask
  sqe.len = addFlags

proc prepPollRemove*(sqe: ptr IoUringSqe, userData: uint64) {.inline.} =
  sqe.opcode = IORING_OP_POLL_REMOVE.uint8
  sqe.paddr = userData

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
    features*:      uint32  # IORING_FEAT_* bits reported by io_uring_setup
    probed:         bool    # IORING_REGISTER_PROBE ran
    supportedOps:   array[56, bool]  # per-opcode support (index = opcode)
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
  result.features = params.features

# ── Feature detection (IORING_REGISTER_PROBE) ─────────────────────────────────

const IO_URING_OP_SUPPORTED* = 1'u16 shl 0   # io_uring_probe_op.flags bit

proc registerProbe*(ring: Ring): bool {.gcsafe.} =
  ## Probe which opcodes the running kernel supports (IORING_REGISTER_PROBE),
  ## caching the per-opcode bitmap in `supportedOps`. This is authoritative —
  ## unlike guessing from the kernel version, it reflects seccomp/container
  ## restrictions and backported features. Returns false when the probe is not
  ## available (older kernel / seccomp / restricted io_uring); callers should
  ## then assume a safe baseline rather than enabling fast paths. A failed
  ## probe leaves `probed` clear so `supports()` stays permissive (the kernel
  ## returns -EINVAL/-EOPNOTSUPP per-op at runtime and the backends fall back).
  if ring.probed:
    return true
  # The probe buffer carries `struct io_uring_probe` followed by
  # IORING_OP_LAST io_uring_probe_op entries.
  const OpCount = 56   # IORING_OP_LAST = 55, ops[0..54]
  var buf = newSeq[byte](sizeof(IoUringProbe) + OpCount * sizeof(IoUringProbeOp))
  zeroMem(addr buf[0], buf.len)
  let probe = cast[ptr IoUringProbe](addr buf[0])
  let ops = cast[ptr UncheckedArray[IoUringProbeOp]](
    cast[int](probe) + sizeof(IoUringProbe))
  let ret = ioUringRegister(ring.ringFd, IORING_REGISTER_PROBE,
                            cast[clong](addr buf[0]), buf.len.cuint)
  if ret < 0:
    return false
  ring.probed = true
  let count = min(probe.opsLen.int, OpCount)
  for i in 0 ..< count:
    let op = ops[i].op.int
    if op >= 0 and op < OpCount:
      ring.supportedOps[op] = (ops[i].flags and IO_URING_OP_SUPPORTED) != 0
  true

proc supports*(ring: Ring, opcode: int): bool {.inline, gcsafe.} =
  ## True when `opcode` was reported as supported by the kernel probe. Falls
  ## back to a permissive default when the probe was unavailable (older kernel
  ## / seccomp): the kernel returns -EINVAL/-EOPNOTSUPP per-op at runtime and
  ## the backends already fall back on those.
  if ring.probed:
    return opcode >= 0 and opcode < ring.supportedOps.len and
           ring.supportedOps[opcode]
  true

proc hasFeature*(ring: Ring, feat: uint32): bool {.inline, gcsafe.} =
  ## True when the ring reports `feat` in its IORING_FEAT_* feature set.
  (ring.features and feat) != 0

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

proc pendingSubmit*(ring: Ring): uint32 {.inline, gcsafe.} =
  ## Number of SQEs claimed but not yet handed to the kernel. Callers that
  ## queue many ops in one iteration (e.g. the accept batch) use this to leave
  ## ring space for the timeout op so the loop can always sleep safely.
  ring.sqTail[] - ring.lastSubmit

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
    # Interrupted: the kernel may have consumed only part of the SQEs. Sync to
    # its real head (the shared SQ ring head) so any unsubmitted SQE stays
    # pending instead of being treated as consumed.
    ring.lastSubmit = ring.sqHead[]
    return -EINTR
  if ret >= 0:
    # The kernel consumes exactly `ret` SQEs, which is not always `toSubmit`: an
    # op may complete instantly and satisfy `minComplete` before every SQE is
    # taken (observed: multishot ACCEPT rejected with -EINVAL on WSL2 6.18, so a
    # blocking enter submitted 1 of 2 SQEs and returned). Advance by `ret` only;
    # advancing to sqTail would leave a still-pending SQE (e.g. the armed
    # TIMEOUT) counted as consumed, letting a later `getSqe` wrap around and
    # overwrite its slot — silently dropping the op and hanging the loop forever
    # in `io_uring_enter(minComplete=1)`.
    ring.lastSubmit += ret.uint32
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
