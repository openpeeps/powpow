---
title: simdscan
description: "The SIMD scanning API: SSE2-accelerated CRLF and CRLFCRLF detection with a scalar fallback."
keywords: ["powpow", "api", "simd", "simdscan", "crlf", "sse2"]
---

# simdscan

SIMD-accelerated CRLF / CRLFCRLF scanning (SSE2 with scalar fallback).
Source: `src/powpow/proto/simdscan.nim`. Guide: [performance](../performance.md).

## Constants

```nim
hasSse2* = true    # or false, decided at compile time
MaxRequestLine* = 8192
```

## Procs

```nim
func findCRLFScalar*(buf: ptr UncheckedArray[byte], start, maxLen: int): int {.inline.}
func findDoubleCRLFScalar*(buf: ptr UncheckedArray[byte], start, maxLen: int): int {.inline.}

func findCRLFSse2*(buf: ptr UncheckedArray[byte], start, scanLen: int): int {.inline.}        # SSE2 only
func findDoubleCRLFSse2*(buf: ptr UncheckedArray[byte], start, maxLen: int): int {.inline.}   # SSE2 only

func findCRLF*(buf: ptr UncheckedArray[byte], start, maxLen: int): int {.inline.}
func findDoubleCRLF*(buf: ptr UncheckedArray[byte], start, maxLen: int): int {.inline.}
```

`findCRLF` / `findDoubleCRLF` dispatch to the SSE2 or scalar implementation
based on `hasSse2`. They return the offset of the terminator, or `-1` if not
found within `maxLen`.

## Related

- [http](http.md) — the parser uses these to find header terminators
