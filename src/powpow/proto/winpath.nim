# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## Windows path canonicalization.
##
## `resolveRealWindows` resolves a path's final (junction/symlink-resolved)
## form using `GetFinalPathNameByHandleW`. It lives in its own module so the
## `winlean`/`widestrs` imports cannot clash with powpow's socket types
## (`common.SocketHandle` vs `winlean.SocketHandle`).

when defined(windows):
  import std/[winlean, widestrs, strutils, os]

  proc resolveRealWindows*(path: string): string =
    ## Resolve `path` to its canonical form, following junctions and symlinks
    ## (a junction inside a serve root pointing outside must not escape the
    ## root). Strips the `\\?\` prefix and normalizes separators to `/` so
    ## `withinRoot`'s "/" boundary check works. Falls back to `absolutePath`.
    proc getFinalPathNameByHandleW(hFile: Handle, lpszFilePath: WideCString,
                                   cchFilePath: DWORD, dwFlags: DWORD): DWORD {.
      importc: "GetFinalPathNameByHandleW", stdcall, dynlib: "kernel32".}
    let h = createFileW(newWideCString(path),
                        GENERIC_READ,
                        FILE_SHARE_READ or FILE_SHARE_WRITE or FILE_SHARE_DELETE,
                        nil, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS,
                        Handle(0))
    if h != INVALID_HANDLE_VALUE:
      var buf = newWideCString(65536)
      let n = getFinalPathNameByHandleW(h, buf, DWORD(65536), 0x0)  # FILE_NAME_NORMALIZED
      discard closeHandle(h)
      if n > 0 and n < 65536:
        result = $buf
        if result.startsWith("\\\\?\\"):
          result = result[4 .. ^1]
        result = result.replace("\\", "/")
        return
    result = absolutePath(path).replace("\\", "/")
