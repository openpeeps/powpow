# Package

version       = "0.1.9"
author        = "OpenPeeps"
description   = "High-performance event notification library for Nim"
license       = "MIT"
srcDir        = "src"

# Dependencies

requires "nim >= 2.2.0"
requires "nimsimd >= 1.3.2"
requires "mimedb >= 0.1.1"
requires "openparser >= 0.1.8"
requires "multipart >= 0.1.4"
requires "checksums >= 0.2.2"

# Features

feature "io_uring":
  ## Linux io_uring backend (submission-based I/O). Opt-in: build with
  ## `nimble --features:io_uring <cmd>` or depend via `requires "powpow[io_uring]"`.
  ## Guarded in code with `when defined(features.powpow.io_uring)`.

# Tasks

task test, "Run the unit test suite":
  ## Compile+run every test_*.nim with a SHARED nimcache, so the powpow package
  ## is built once and reused across all tests. The default nimble `test` task
  ## rebuilds the whole package for every test file (~20 full compiles), which
  ## is slow enough on a cold cache to look like a hang.
  ##
  ## `--threads:on` is always used: the threaded tests (test_ratelimit_threads,
  ## test_ws_threads) require it and the rest are unaffected.
  let cache = ".cache/nim/tests"
  let tests = [
    "test_bad_requests", "test_bench_event_loop", "test_dns", "test_findcrlf",
    "test_firefox_regression", "test_http", "test_loop",
    "test_multipart_streamer", "test_net", "test_ratelimit_threads",
    "test_security", "test_signal", "test_sse2", "test_sse2_225",
    "test_sse2_chunk", "test_sse2_direct", "test_sse2_raw",     "test_stream",
    "test_tls", "test_httpclient", "test_httpclient_security",
    "test_ws_client", "test_ws_pool", "test_ws_threads",
  ]
  for t in tests:
    # --outdir keeps the produced test binaries in the (gitignored) cache dir
    # instead of leaving them in tests/.
    exec "nim c -r --threads:on --nimcache:" & cache &
         " --outdir:" & cache & " tests/" & t & ".nim"

task testSmuggler, "Fuzz powpow with the smuggler package (requires smuggler installed)":
  exec "nim c -r --threads:on tests/smuggler_integration.nim"

task testThreads, "Thread-safety smoke tests (--threads:on)":
  exec "nim c -r --threads:on tests/test_ratelimit_threads.nim"
  exec "nim c -r --threads:on tests/test_ws_threads.nim"
