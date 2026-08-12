---
title: Examples index
description: "Every runnable powpow example: HTTP, WebSocket, TCP, UDP, TLS, UDS, timers, signals, rate limiting, fswatch and uploads, with ports and commands."
keywords: ["powpow", "examples", "demos", "tutorial"]
---

# Examples index

Every example lives in [`examples/`](../examples/) and is runnable as-is. Most
are `nim c -r` one-liners; the multi-threaded one needs `--threads:on`.

> The `examples/` directory also contains prebuilt binaries and a 2.76 GB
> `Big_Buck_Bunny_4K.webm` test file — ignore those; only the `.nim` sources
> below are documentation material.

## HTTP servers

| Example | Demo | Run | Port/URL |
|---|---|---|---|
| [`httpserver.nim`](../examples/httpserver.nim) | Tiny HTTP/1.1 server, manual routing | `nim c -r examples/httpserver.nim` | `http://localhost:9000` |
| [`httpserver_threads.nim`](../examples/httpserver_threads.nim) | One event loop per CPU core, `SO_REUSEPORT` | `nim c -r --threads:on examples/httpserver_threads.nim` | `http://localhost:9000` |
| [`static_server.nim`](../examples/static_server.nim) | Static site (`serveStatic`) + CORS + JSON API | `nim c -r examples/static_server.nim` | `http://localhost:9004` |
| [`stream_server.nim`](../examples/stream_server.nim) | `streamFile`/`sendFile`/`serveFile` streaming & resume | `nim c -r examples/stream_server.nim` (needs the `.webm`) | `http://localhost:9002` |
| [`upload_server.nim`](../examples/upload_server.nim) | File uploads: `streamToFile` + `getMultipart` | `nim c -r examples/upload_server.nim` | `http://localhost:9000` |
| [`uds_server.nim`](../examples/uds_server.nim) | HTTP over a Unix domain socket | `nim c -r examples/uds_server.nim` | UDS `/tmp/powpow.sock` |
| [`tls_server.nim`](../examples/tls_server.nim) | HTTPS with an embedded self-signed cert | `nim c -r examples/tls_server.nim` | `https://localhost:9443` |

## WebSocket

| Example | Demo | Run | Port/URL |
|---|---|---|---|
| [`wsserver.nim`](../examples/wsserver.nim) | Standalone WebSocket server | `nim c -r examples/wsserver.nim` | `ws://localhost:9001` |
| [`wsupgrade.nim`](../examples/wsupgrade.nim) | HTTP + WebSocket on one port | `nim c -r examples/wsupgrade.nim` | `http://localhost:9000`, `ws://localhost:9000/ws` |
| [`ws_chat.nim`](../examples/ws_chat.nim) | Multi-client chat with broadcast | `nim c -r examples/ws_chat.nim` | `http://localhost:9006`, `ws://localhost:9006/ws` |

## TCP

| Example | Demo | Run | Port/URL |
|---|---|---|---|
| [`tcp_chat.nim`](../examples/tcp_chat.nim) | Multi-client chat room on raw TCP | `nim c -r examples/tcp_chat.nim` | `nc 127.0.0.1 9010` |
| [`tcp_client.nim`](../examples/tcp_client.nim) | Interactive stdin client for the chat | `nim c -r examples/tcp_client.nim` | connects to `127.0.0.1:9010` |
| [`tcp_proxy.nim`](../examples/tcp_proxy.nim) | TCP reverse proxy / load balancer | `nim c -r examples/tcp_proxy.nim` | `nc 127.0.0.1 9020` (backend `:9021`) |

## UDP

| Example | Demo | Run | Port/URL |
|---|---|---|---|
| [`udp_echo.nim`](../examples/udp_echo.nim) | UDP echo server + `--client` ping mode | `nim c -r examples/udp_echo.nim` | `0.0.0.0:9011` |

## Core features

| Example | Demo | Run | Notes |
|---|---|---|---|
| [`timers_scheduler.nim`](../examples/timers_scheduler.nim) | Timer wheel: one-shot, interval, deferred, idle | `nim c -r examples/timers_scheduler.nim` | ~8s, no I/O |
| [`fswatch.nim`](../examples/fswatch.nim) | File system watcher | `nim c -r examples/fswatch.nim` | watches `/tmp/powpow-test.txt` |
| [`os_signals.nim`](../examples/os_signals.nim) | Graceful shutdown on SIGINT/SIGTERM | `nim c -r examples/os_signals.nim` | `http://127.0.0.1:9007`, Ctrl+C |
| [`signal_bus.nim`](../examples/signal_bus.nim) | In-process pub/sub `SignalRelay` | `nim c -r examples/signal_bus.nim` | `http://localhost:9005/emit?signal=N` |
| [`stream_pipe.nim`](../examples/stream_pipe.nim) | `IoStream` socketpair echo + EOF | `nim c -r examples/stream_pipe.nim` | none — terminal demo |
| [`ratelimit_server.nim`](../examples/ratelimit_server.nim) | Sliding-window per-IP rate limiting | `nim c -r examples/ratelimit_server.nim` | `http://localhost:9003` (5 req/10s) |

## Suggested test commands

```bash
# HTTP server
curl http://localhost:9000/
curl http://localhost:9000/hello
curl http://localhost:9000/api/echo -d 'Hello powpow!'

# WebSocket
websocat ws://localhost:9001          # or: npx wscat -c ws://localhost:9001
websocat ws://localhost:9006/ws

# TCP chat / proxy
nc 127.0.0.1 9010
nc 127.0.0.1 9020

# UDP
echo "hello udp" | nc -u -w1 127.0.0.1 9011
nim c -r examples/udp_echo.nim -- --client

# TLS
curl -k https://localhost:9443/hello

# UDS
curl --unix-socket /tmp/powpow.sock http://localhost/hello

# Static site
curl http://localhost:9004/static/index.html
curl -H "Origin: https://example.com" -i http://localhost:9004/static/index.html

# Rate limiting — 429 after the 5th request
for i in $(seq 6); do curl -w "\n%{http_code}\n" http://localhost:9003/; done

# Uploads
curl -X POST http://localhost:9000/upload/raw --data-binary @bigfile.bin
curl -X POST http://localhost:9000/upload/stream -F "file=@bigfile.bin"

# Signal bus
curl "http://localhost:9005/emit?signal=1"
curl "http://localhost:9005/emit?signal=3"

# File system watching (in a second terminal)
echo "hello" >> /tmp/powpow-test.txt
mv /tmp/powpow-test.txt /tmp/powpow-test2.txt
rm /tmp/powpow-test2.txt
```

## Port map

| Port | Example |
|---|---|
| 9000 | `httpserver`, `httpserver_threads`, `wsupgrade`, `upload_server` |
| 9001 | `wsserver` |
| 9002 | `stream_server` |
| 9003 | `ratelimit_server` |
| 9004 | `static_server` |
| 9005 | `signal_bus` |
| 9006 | `ws_chat` |
| 9007 | `os_signals` |
| 9010 / 9011 | `tcp_chat` / `tcp_client`, `udp_echo` |
| 9020 / 9021 | `tcp_proxy` (and its backend) |
| 9443 | `tls_server` |
| none | `timers_scheduler`, `fswatch`, `stream_pipe` |
| UDS path | `uds_server` (`/tmp/powpow.sock`) |
