---
title: tlsapi
description: "The raw OpenSSL bindings used by the TLS layer: SSL_CTX, SSL, handshake and error procs."
keywords: ["powpow", "api", "tlsapi", "openssl", "ssl"]
---

# tlsapi

Minimal direct-link OpenSSL bindings (`-lssl -lcrypto`) used by `tls.nim`.
Source: `src/powpow/net/tlsapi.nim`. Guide: [TLS](../net/tls.md).

## Types

```nim
SslCtx* = pointer    # SSL_CTX*
SslPtr* = pointer    # SSL*
```

## Constants

```nim
SSL_FILETYPE_PEM* = 1
SSL_VERIFY_NONE* = 0
SSL_VERIFY_PEER* = 1
SSL_ERROR_NONE* = 0
SSL_ERROR_SSL* = 1
SSL_ERROR_WANT_READ* = 2
SSL_ERROR_WANT_WRITE* = 3
SSL_ERROR_SYSCALL* = 5
SSL_ERROR_ZERO_RETURN* = 6
SSL_CTRL_SET_TLSEXT_HOSTNAME* = 55
```

## Procs

```nim
proc TLS_server_method*(): pointer
proc TLS_client_method*(): pointer

proc SSL_CTX_new*(m: pointer): SslCtx
proc SSL_CTX_free*(c: SslCtx)
proc SSL_CTX_use_certificate_file*(c: SslCtx, file: cstring, typ: cint): cint
proc SSL_CTX_use_PrivateKey_file*(c: SslCtx, file: cstring, typ: cint): cint
proc SSL_CTX_check_private_key*(c: SslCtx): cint
proc SSL_CTX_set_verify*(c: SslCtx, mode: cint, cb: pointer)
proc SSL_CTX_set_default_verify_paths*(c: SslCtx): cint

proc SSL_new*(c: SslCtx): SslPtr
proc SSL_free*(s: SslPtr)
proc SSL_set_fd*(s: SslPtr, fd: cint): cint
proc SSL_set_accept_state*(s: SslPtr)
proc SSL_set_connect_state*(s: SslPtr)
proc SSL_do_handshake*(s: SslPtr): cint
proc SSL_read*(s: SslPtr, buf: pointer, num: cint): cint
proc SSL_write*(s: SslPtr, buf: pointer, num: cint): cint
proc SSL_shutdown*(s: SslPtr): cint
proc SSL_get_error*(s: SslPtr, ret: cint): cint
proc SSL_ctrl*(s: SslPtr, cmd: cint, larg: clong, parg: pointer): culong
proc SSL_set1_host*(s: SslPtr, hostname: cstring): cint

proc ERR_get_error*(): culong
proc ERR_error_string_n*(e: culong; buf: cstring; len: csize_t)
proc opensslError*(): string
```

## Related

- [tls](tls.md) — the higher-level layer built on these bindings
