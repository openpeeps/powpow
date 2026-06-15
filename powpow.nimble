# Package

version       = "0.1.0"
author        = "George Lemon"
description   = "High-performance event notification library for Nim"
license       = "MIT"
srcDir        = "src"

# Tasks

task test, "Run all tests":
  exec "nim c -r tests/test_loop.nim"
  exec "nim c -r tests/test_net.nim"
  exec "nim c -r tests/test_http.nim"

# Dependencies

requires "nim >= 2.2.2"
requires "nimsimd >= 0.1.0"
requires "mimedb"