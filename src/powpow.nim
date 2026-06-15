# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow — High-performance event notification library for Nim.
##
## This is the main entry point. Importing `powpow` gives you everything:
##
##   import powpow
##
##   let loop = newLoop()
##   loop.register(fd, {Read}, proc(fd: int, ev: set[EventType]) =
##     echo "fd ", fd, " is readable!"
##   )
##   loop.run()

import powpow/[types, platform, loop, net, proto]

export types
export platform except close  # close is on Loop
export loop
export net
export proto
