# Package

version       = "0.1.3"
author        = "George Lemon"
description   = "High-performance event notification library for Nim"
license       = "LGPL-3.0-or-later"
srcDir        = "src"

# Tasks

task test, "Run all tests":
  exec "nim c -r tests/test_loop.nim"
  exec "nim c -r tests/test_net.nim"
  exec "nim c -r tests/test_http.nim"
  exec "nim c -r tests/test_bench_event_loop.nim"
  exec "nim c -r tests/test_security.nim"


# Dependencies

requires "nim >= 2.2.2"
requires "nimsimd >= 0.1.0"
requires "mimedb >= 0.1.0"
requires "openparser >= 0.1.0"
requires "multipart >= 0.1.2"
requires "checksums > = 0.1.0"
