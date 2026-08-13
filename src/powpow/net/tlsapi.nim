# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
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
  BioPtr* = pointer  ## `BIO*`

const
  SSL_FILETYPE_PEM* = 1
  SSL_VERIFY_NONE*  = 0
  SSL_VERIFY_PEER*  = 1

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
proc SSL_CTX_set_default_verify_paths*(c: SslCtx): cint {.
  importc: "SSL_CTX_set_default_verify_paths".}

proc SSL_new*(c: SslCtx): SslPtr {.importc: "SSL_new".}
proc SSL_free*(s: SslPtr) {.importc: "SSL_free".}
proc SSL_set_fd*(s: SslPtr; fd: cint): cint {.importc: "SSL_set_fd".}
proc SSL_set_bio*(s: SslPtr; rbio, wbio: BioPtr) {.importc: "SSL_set_bio".}
proc SSL_get_rbio*(s: SslPtr): BioPtr {.importc: "SSL_get_rbio".}
proc SSL_get_wbio*(s: SslPtr): BioPtr {.importc: "SSL_get_wbio".}
proc SSL_get_pending_write*(s: SslPtr): cint {.importc: "SSL_get_pending_write".}
proc BIO_new*(b: BioPtr): BioPtr {.importc: "BIO_new".}
proc BIO_s_mem*(): BioPtr {.importc: "BIO_s_mem".}
proc BIO_write*(b: BioPtr; buf: pointer; len: cint): cint {.importc: "BIO_write".}
proc BIO_read*(b: BioPtr; buf: pointer; len: cint): cint {.importc: "BIO_read".}
proc SSL_set_accept_state*(s: SslPtr) {.importc: "SSL_set_accept_state".}
proc SSL_set_connect_state*(s: SslPtr) {.importc: "SSL_set_connect_state".}
proc SSL_do_handshake*(s: SslPtr): cint {.importc: "SSL_do_handshake".}
proc SSL_read*(s: SslPtr; buf: pointer; num: cint): cint {.importc: "SSL_read".}
proc SSL_write*(s: SslPtr; buf: pointer; num: cint): cint {.importc: "SSL_write".}
proc SSL_shutdown*(s: SslPtr): cint {.importc: "SSL_shutdown".}
proc SSL_get_error*(s: SslPtr; ret: cint): cint {.importc: "SSL_get_error".}
proc SSL_ctrl*(s: SslPtr; cmd: cint; larg: cint; parg: pointer): cint {.
  importc: "SSL_ctrl".}
proc SSL_set1_host*(s: SslPtr; hostname: cstring): cint {.
  importc: "SSL_set1_host".}

const SSL_CTRL_SET_TLSEXT_HOSTNAME* = 55
  ## `SSL_set_tlsext_host_name` is a macro over `SSL_ctrl` in OpenSSL 1.1.1+/3,
  ## so it is not linkable; use SSL_ctrl with this command for SNI.

proc ERR_get_error*(): culong {.importc: "ERR_get_error".}
proc ERR_error_string_n*(e: culong; buf: cstring; len: csize_t) {.
  importc: "ERR_error_string_n".}

proc opensslError*(): string =
  ## Most recent OpenSSL error from the queue, or "" if empty.
  ## Uses the length-bounded ERR_error_string_n (ERR_error_string's static
  ## buffer is not thread-safe, and the unbounded form can overflow a fixed
  ## buffer).
  let e = ERR_get_error()
  if e == 0: return ""
  var buf {.noinit.}: array[256, char]
  ERR_error_string_n(e, cast[cstring](addr buf[0]), buf.len.csize_t)
  result = $cast[cstring](addr buf[0])
