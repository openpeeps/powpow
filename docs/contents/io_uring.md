---
title: io_uring
description: "The opt-in Linux io_uring backend: submission-based I/O, zero-copy send_zc, splice file sends, registered buffers and the full io_uring API binding."
keywords: ["powpow", "io_uring", "linux", "zero-copy", "send_zc", "splice", "registered buffers"]
---

# io_uring backend

powpow ships an **opt-in Linux `io_uring` backend** (submission-based I/O) in
addition to the default readiness backends (`epoll`/`kqueue`/`IOCP`). Instead of
"the socket is readable/writable" readiness events, every operation — accept,
connect, recv, send, shutdown, file transfer, timeout — is submitted to the
kernel's ring and reported back through a completion.

The whole backend is implemented on **raw `io_uring_setup` / `io_uring_enter` /
`io_uring_register` syscalls** — there is no liburing dependency.

## Enabling it

```bash
nimble --features:io_uring run examples/httpserver.nim    # nimble feature
nim c -d:powpowIoUring examples/httpserver.nim           # direct build
requires "powpow[io_uring]"                               # as a dependency
```

Requirements:

- **Linux >= 5.6** (`io_uring_setup`; multishot accept needs 6.0, zero-copy
  send needs 6.0, registered buffers are 5.5+ with tagged updates on 5.19+).
- The kernel must allow `io_uring` (seccomp/container restrictions disable it —
  the backend then refuses to start rather than silently degrading).

The same public API works on both backends: `newLoop`, `newTcpServer`,
`newHttpServer`, `conn.send`, `res.sendFile`, … switch the backend by changing
the build flag, not the code.

## Architecture

The io_uring backend is a single-iteration loop:

1. **Reap** completions (posted by the previous `io_uring_enter`).
2. Queue re-arms, new ops and the kernel timeout.
3. **Submit everything in one `io_uring_enter`**, which blocks only when the
   iteration did no work and a timeout is actually armed.

Key properties:

- **One `io_uring_enter` per loop iteration** — no per-op syscall on the hot
  path.
- **Op-driven, not readiness-driven.** Connections keep one
  `IORING_OP_ACCEPT`/`RECV`/`SEND` in flight each; the kernel arms an internal
  poll when the socket is not ready (`IORING_FEAT_FAST_POLL`), so no separate
  poll step is needed.
- **Feature detection by `IORING_REGISTER_PROBE`**, not kernel-version
  guessing. The ring caches a per-opcode support bitmap; fast paths (multishot
  accept, `send_zc`, splice, shutdown, registered buffers) check it at runtime
  and fall back gracefully. (`IORING_REGISTER_PROBE` returns `-EINVAL` on the
  WSL2 6.18 kernel; a failed probe leaves support "permissive" and the runtime
  `-EINVAL` fallbacks handle it.)
- **Fixed files** (`IORING_REGISTER_FILES` + `IOSQE_FIXED_FILE`) are on by
  default, indexed by fd number, with a synchronous update per accept/close.
  `-d:powpowNoFixedFiles` disables them (the WSL2 A/B shows them at parity).

## Operations used

| Area | Op |
|---|---|
| Listen | `IORING_OP_ACCEPT` (one-shot batch, or multishot on kernel ≥ 6.0) |
| Connect | `IORING_OP_CONNECT` |
| Read | `IORING_OP_RECV` (one-shot, or multishot + buffer-select under `-d:powpowBufferSelect`) |
| Write | `IORING_OP_SEND`, and `IORING_OP_SEND_ZC` for large payloads |
| File → socket | `IORING_OP_SPLICE` (file → pipe → socket), fallback `READ` + `SEND` |
| Graceful close | `sockShutdown(2)` by default; `IORING_OP_SHUTDOWN` opt-in |
| Idle wait | `IORING_OP_TIMEOUT` (armed only when the ring has a free slot) |
| Buffer pools | `IORING_OP_PROVIDE_BUFFERS` / `REMOVE_BUFFERS`; `IORING_REGISTER_BUFFERS` |
| Wake | `POLL_ADD` on an `eventfd` |

## Zero-copy

### `send_zc` — zero-copy sends

Large writes are sent with `IORING_OP_SEND_ZC`: the kernel pins the buffer's
pages and reports two completions — a data completion (`IORING_CQE_F_MORE`) and
a **notification** (`IORING_CQE_F_NOTIF`) that the pages may be reused. powpow
keeps the write token set until the notification, so the write buffer is never
touched while the kernel still references it.

- Enabled by default when the opcode probe succeeds; `-d:powpowNoSendZc`
  disables it, `-d:powpowSendZcThreshold=N` sets the size threshold (default
  **64 KiB** — smaller payloads use a plain SEND, where pinning costs more than
  the copy it saves).
- If a kernel rejects the op (`-EINVAL`/`-EOPNOTSUPP`), the backend disables it
  for the loop and retries the same buffer as a plain SEND.

### `SPLICE` — zero-copy file sends

Static files go through `IORING_OP_SPLICE` (file → a per-connection pipe →
socket), moving pages straight from the page cache to the socket with **no
user-space copy**. The pipe is per-connection (a shared FIFO would interleave
concurrent transfers) and sized to two `SpliceChunkSize` (default **1 MiB**)
chunks. Falls back to the `READ` + `SEND` chunk pump when splice is unavailable.

### Registered buffers

`IORING_REGISTER_BUFFERS` lets fixed ops reference buffers by index without
per-op page pinning. powpow exposes the full register/update/unregister
lifecycle (`ring.registerBuffers`, `registerBuffersUpdate`,
`unregisterBuffers`) and uses it for:

- the `powpowBufferSelect` read group, and
- opt-in `-d:powpowSendZcFixed`: a per-loop registered send buffer that large
  writes are copied into once and then sent with `SEND_ZC_FIXED` (released by
  its notification; only one such op can be in flight per loop).

## API binding surface

`src/powpow/io/uring.nim` binds the **entire io_uring API** against
`linux/io_uring.h`:

- every opcode (0–54), all `IORING_REGISTER_*` ops, `IORING_SETUP_*` /
  `IORING_ENTER_*` / `IOSQE_*` / `IORING_CQE_F_*` / `IORING_FEAT_*` flags;
- the ABI structs (`io_uring_probe`, `io_uring_rsrc_*`, `io_uring_buf(_ring)`,
  `io_uring_getevents_arg`, `io_uring_sync_cancel_reg`, …);
- `io_uring_prep_*`-style helpers (`prepRead`, `prepSend`, `prepSendZc`,
  `prepSplice`, `prepAccept`, `prepConnect`, `prepTimeout`, `prepCancel`,
  `prepShutdown`, `prepFilesUpdate`, `prepMsgRing`, `prepPollAdd`, …).

There is **no `IORING_OP_SENDFILE`** in the kernel — the value 40 is
`IORING_OP_MSG_RING`. File → socket transfers use `SPLICE` or a `READ`+`SEND`
pump, never a nonexistent opcode.

## Configuration

| Define | Effect |
|---|---|
| `powpowIoUring` (or `features.powpow.io_uring`) | enable the backend |
| `powpowNoSendZc` | disable `SEND_ZC` |
| `powpowSendZcThreshold=N` | minimum payload size for `SEND_ZC` (default 65536) |
| `powpowSendZcFixed` | use a registered buffer + `SEND_ZC_FIXED` |
| `powpowNoSplice` | disable `SPLICE` file sends |
| `powpowSpliceChunk=N` | splice chunk / pipe size (default 1 MiB) |
| `powpowShutdownOp` | use `IORING_OP_SHUTDOWN` instead of `sockShutdown` (costs ~40% in `Connection: close` mode) |
| `powpowNoFixedFiles` | disable `IORING_REGISTER_FILES` |
| `powpowFixedFiles=N` | fixed-file table size (default 8192) |
| `powpowBufferSelect` | multishot `RECV` + provided-buffer group |
| `powpowNoMultishotAccept` | force the one-shot accept batch |

## Performance

On the WSL2 6.18 box the io_uring backend is at parity with epoll across the
wrk benchmarks (keep-alive, `Connection: close`, static files), and the
zero-copy paths (`send_zc`, splice) remove the user-space copies that the
readiness backend's `sendfile(2)` path performs. A single 10 MB transfer runs
at ~600 MB/s via splice vs ~650 MB/s via `sendfile(2)` — the gap is the
per-op completion round-trip, which the connection-bound benchmarks hide
completely.
