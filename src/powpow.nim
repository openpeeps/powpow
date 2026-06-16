# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## This is a high-performance, event notification library for Nim. It provides a low-level event loop and timer wheel,
## as well as higher-level abstractions for building TCP/UDP, HTTP and WebSocket servers. 
## 
## The library is designed to be minimal and efficient, with a focus on low-latency event handling and minimal overhead,
## providing a solid foundation for building high-performance networked applications in Nim.
## 
## Features:
## - Single-threaded, non-blocking event loop with edge-triggered I/O events
## - Hierarchical timer wheel for efficient timer management
## - Support for one-shot and repeating timers, deferred callbacks, and idle handlers

import powpow/[types, platform, loop, net, proto]

export types
export platform except close  # close is on Loop
export loop
export net
export proto
