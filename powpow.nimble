# Package

version       = "0.1.8"
author        = "George Lemon"
description   = "High-performance event notification library for Nim"
license       = "LGPL-3.0-or-later"
srcDir        = "src"

# Dependencies

requires "nim >= 2.2.0"
requires "nimsimd >= 0.1.0"
requires "mimedb >= 0.1.0"
requires "openparser >= 0.1.6"
requires "multipart >= 0.1.2"
requires "checksums > = 0.1.0"

# Tasks

task testSmuggler, "Fuzz powpow with the smuggler package (requires smuggler installed)":
  exec "nim c -r --threads:on tests/test_smuggler_integration.nim"

task testThreads, "Thread-safety smoke tests (--threads:on)":
  exec "nim c -r --threads:on tests/test_ratelimit_threads.nim"