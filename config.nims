# config.nims — io_uring is OPT-IN and epoll remains the Linux default.
#
# This file deliberately does NOT change any compiler flags. The io_uring
# backend must be selected explicitly, exactly like any consumer of the
# library would:
#
#   nim c -d:powpowIoUring ...                      # direct nim build
#   clue test --features:io_uring                   # clue
#   nimble --features:io_uring <cmd>                # nimble feature
#   requires "powpow[io_uring]"                     # dependent package
#
# Enabling it here (e.g. `when defined(linux): switch("define",
# "features.powpow.io_uring")`) silently changes the repo's default build on
# Linux, which regresses the epoll path in benchmarks and tests.
