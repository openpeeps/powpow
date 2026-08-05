import std/os
switch("path", "$projectDir/../src")
# The multipart dependency is developed alongside powpow; tests compile against
# the local checkout which includes the per-file size-limit enforcement.
switch("path", getHomeDir() & "/Development/packages/multipart/src")
