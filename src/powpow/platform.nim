# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/platform.nim — Compile-time platform backend selector.
##
## Automatically selects the best I/O multiplexing backend for the host OS:
## - Linux          → epoll
## - macOS / BSD    → kqueue
## - Windows        → (future: IOCP, falls back to poll for now)
## - Everything else → poll(2)
import ./types
export types

when defined(windows):
  import platform/iocp
  export iocp
elif defined(linux):
  import platform/epoll
  export epoll
elif defined(macosx) or defined(bsd):
  import platform/kqueue
  export kqueue
else:
  import platform/poll
  export poll
