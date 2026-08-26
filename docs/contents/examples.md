---
title: Examples
description: "Every runnable powpow example, each with full source and a walkthrough: HTTP, WebSocket, TCP, UDP, DTLS, TLS, UDS, clients, timers, signals and rate limiting."
keywords: ["powpow", "examples", "demos", "tutorial"]
---

# Examples

Every example lives in [`examples/`](../examples/) and is runnable as-is.
Each one has its own page here with the complete source pasted in and a
walkthrough of the interesting parts. Ignore prebuilt binaries in
`examples/`; only the `.nim` sources matter.

## HTTP servers

| Example | Demo | Page |
|---|---|---|
| `httpserver.nim` | Tiny HTTP/1.1 server, manual routing | [httpserver](examples/httpserver.md) |
| `httpserver_threads.nim` | One loop per core via `SO_REUSEPORT` | [httpserver_threads](examples/httpserver-threads.md) |
| `static_server.nim` | Static site + CORS + JSON API | [static_server](examples/static-server.md) |
| `stream_server.nim` | `streamFile` / `sendFile` / `serveFile`, Range & resume | [stream_server](examples/stream-server.md) |
| `upload_server.nim` | Raw-body and multipart uploads | [upload_server](examples/upload-server.md) |
| `uds_server.nim` | HTTP over a Unix domain socket | [uds_server](examples/uds-server.md) |
| `tls_server.nim` | HTTPS with an embedded self-signed cert | [tls_server](examples/tls-server.md) |

## Clients

| Example | Demo | Page |
|---|---|---|
| `httpclient.nim` | Sync + async HTTP client, pooling, UDS | [httpclient](examples/httpclient.md) |

## WebSocket

| Example | Demo | Page |
|---|---|---|
| `wsserver.nim` | Standalone WebSocket server | [wsserver](examples/wsserver.md) |
| `wsclient.nim` | High-level client: reconnect, sendMessage | [wsclient](examples/wsclient.md) |
| `wsupgrade.nim` | HTTP and WebSocket on one port | [wsupgrade](examples/wsupgrade.md) |
| `ws_chat.nim` | Multi-client chat with broadcast | [ws_chat](examples/ws-chat.md) |

## TCP

| Example | Demo | Page |
|---|---|---|
| `tcp_chat.nim` | Multi-client chat room on raw TCP | [tcp_chat](examples/tcp-chat.md) |
| `tcp_client.nim` | Interactive stdin client for the chat | [tcp_client](examples/tcp-client.md) |
| `tcp_proxy.nim` | Reverse proxy / load balancer with connect buffering | [tcp_proxy](examples/tcp-proxy.md) |

## UDP and DTLS

| Example | Demo | Page |
|---|---|---|
| `udp_echo.nim` | UDP echo server plus ping client mode | [udp_echo](examples/udp-echo.md) |
| `dtls_echo.nim` | DTLS 1.2 echo with cookie exchange and MTU splitting | [dtls_echo](examples/dtls-echo.md) |

## Core features

| Example | Demo | Page |
|---|---|---|
| `timers_scheduler.nim` | Timer wheel: one-shot, interval, deferred, idle | [timers_scheduler](examples/timers-scheduler.md) |
| `fswatch.nim` | File system watcher events | [fswatch](examples/fswatch.md) |
| `os_signals.nim` | Graceful shutdown on SIGINT / SIGTERM | [os_signals](examples/os-signals.md) |
| `signal_bus.nim` | In-process pub/sub `SignalRelay` | [signal_bus](examples/signal-bus.md) |
| `stream_pipe.nim` | `IoStream` socketpair echo with EOF | [stream_pipe](examples/stream-pipe.md) |
| `ratelimit_server.nim` | Sliding-window per-IP rate limiting | [ratelimit](examples/ratelimit.md) |

## Port map

| Port | Example |
|---|---|
| 9000 | `httpserver`, `httpserver_threads`, `wsupgrade`, `upload_server` |
| 9001 | `wsserver` |
| 9002 | `stream_server` (needs the ~2.76 GB `.webm`) |
| 9003 | `ratelimit_server` |
| 9004 | `static_server` |
| 9005 | `signal_bus` |
| 9006 | `ws_chat` |
| 9007 | `os_signals` |
| 9010 | `tcp_chat` and `tcp_client` |
| 9011 | `udp_echo` |
| 9012 | `dtls_echo` |
| 9020 / 9021 | `tcp_proxy` and its backend |
| 9443 | `tls_server` |
| none | `timers_scheduler`, `fswatch`, `stream_pipe`, `httpclient` |
| UDS path | `uds_server` (`/tmp/powpow.sock`) |

## Quick smoke test

```bash
# HTTP server
curl http://localhost:9000/
curl http://localhost:9000/api/echo -d 'Hello powpow!'

# WebSocket
websocat ws://localhost:9001          # or: npx wscat -c ws://localhost:9001

# TCP chat
nc 127.0.0.1 9010

# UDP
echo "hello udp" | nc -u -w1 127.0.0.1 9011
nim c -r examples/udp_echo.nim -- --client

# TLS and DTLS
curl -k https://localhost:9443/hello
nim c -r examples/dtls_echo.nim -- --client

# UDS
curl --unix-socket /tmp/powpow.sock http://localhost/hello

# Rate limiting (429 after the 5th request)
for i in $(seq 6); do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:9003/; done

# Uploads
curl -X POST http://localhost:9000/upload/raw --data-binary @bigfile.bin
curl -X POST http://localhost:9000/upload/stream -F "file=@bigfile.bin"
```
