# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## powpow/net/tlsapi.nim — Minimal OpenSSL bindings used by powpow's TLS layer.
##
## Unlike `std/openssl` (which `dlopen`s a versioned `libssl` at runtime and can
## accidentally mix libraries), this module declares the handful of OpenSSL
## entry points powpow needs and links `libssl`/`libcrypto` directly at compile
## time, so the whole process always uses a single, deterministic TLS library.
##
## The bindings are declared with `{.importc.}` and no header, so they work as
## long as the linker can find `-lssl -lcrypto` (system, Homebrew, MacPorts, ...).

when not defined(windows):
  {.passL: "-lssl -lcrypto".}

type
  SslCtx* = pointer  ## `SSL_CTX*`
  SslPtr* = pointer  ## `SSL*`

const
  SSL_FILETYPE_PEM* = 1
  SSL_VERIFY_NONE*  = 0

  SSL_ERROR_NONE*       = 0
  SSL_ERROR_SSL*        = 1
  SSL_ERROR_WANT_READ*  = 2
  SSL_ERROR_WANT_WRITE* = 3
  SSL_ERROR_SYSCALL*    = 5
  SSL_ERROR_ZERO_RETURN* = 6

proc TLS_server_method*(): pointer {.importc: "TLS_server_method".}
proc TLS_client_method*(): pointer {.importc: "TLS_client_method".}

proc SSL_CTX_new*(m: pointer): SslCtx {.importc: "SSL_CTX_new".}
proc SSL_CTX_free*(c: SslCtx) {.importc: "SSL_CTX_free".}
proc SSL_CTX_use_certificate_file*(c: SslCtx; file: cstring; typ: cint): cint {.
  importc: "SSL_CTX_use_certificate_file".}
proc SSL_CTX_use_PrivateKey_file*(c: SslCtx; file: cstring; typ: cint): cint {.
  importc: "SSL_CTX_use_PrivateKey_file".}
proc SSL_CTX_check_private_key*(c: SslCtx): cint {.
  importc: "SSL_CTX_check_private_key".}
proc SSL_CTX_set_verify*(c: SslCtx; mode: cint; cb: pointer) {.
  importc: "SSL_CTX_set_verify".}

proc SSL_new*(c: SslCtx): SslPtr {.importc: "SSL_new".}
proc SSL_free*(s: SslPtr) {.importc: "SSL_free".}
proc SSL_set_fd*(s: SslPtr; fd: cint): cint {.importc: "SSL_set_fd".}
proc SSL_set_accept_state*(s: SslPtr) {.importc: "SSL_set_accept_state".}
proc SSL_set_connect_state*(s: SslPtr) {.importc: "SSL_set_connect_state".}
proc SSL_do_handshake*(s: SslPtr): cint {.importc: "SSL_do_handshake".}
proc SSL_read*(s: SslPtr; buf: pointer; num: cint): cint {.importc: "SSL_read".}
proc SSL_write*(s: SslPtr; buf: pointer; num: cint): cint {.importc: "SSL_write".}
proc SSL_shutdown*(s: SslPtr): cint {.importc: "SSL_shutdown".}
proc SSL_get_error*(s: SslPtr; ret: cint): cint {.importc: "SSL_get_error".}

proc ERR_get_error*(): culong {.importc: "ERR_get_error".}
proc ERR_error_string*(e: culong; buf: cstring): cstring {.
  importc: "ERR_error_string".}

proc opensslError*(): string =
  ## Most recent OpenSSL error from the queue, or "" if empty.
  let e = ERR_get_error()
  if e == 0: return ""
  var buf = newString(256)
  discard ERR_error_string(e, buf.cstring)
  let z = buf.find('\0')
  result = if z >= 0: buf[0 ..< z] else: buf
