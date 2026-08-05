# Package

version       = "0.1.8"
author        = "George Lemon"
description   = "High-performance event notification library for Nim"
license       = "LGPL-3.0-or-later"
srcDir        = "src"

# Dependencies

requires "nim >= 2.2.0"
requires "nimsimd >= 1.3.2"
requires "mimedb >= 0.1.1"
requires "openparser >= 0.1.8"
requires "multipart >= 0.1.3"
requires "checksums > = 0.2.2"

# Tasks

task testSmuggler, "Fuzz powpow with the smuggler package (requires smuggler installed)":
  exec "nim c -r --threads:on tests/smuggler_integration.nim"

task testThreads, "Thread-safety smoke tests (--threads:on)":
  exec "nim c -r --threads:on tests/test_ratelimit_threads.nim"