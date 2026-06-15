<p align="center">
  <img src="https://github.com/openpeeps/powpow/blob/main/.github/powpow_logo.png" width="80px"><br>
  PowPow 💥  A high-performance, event notification library for Nim
</p>

<p align="center">
  <code>nimble install powpow</code>
</p>

<p align="center">
  <a href="https://openpeeps.github.io/powpow">API reference</a><br>
  <img src="https://github.com/openpeeps/powpow/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/openpeeps/powpow/workflows/docs/badge.svg" alt="Github Actions">
</p>

## 😍 Key Features
- High-performance, event-driven networking library for Nim
- Support for low-level UDP, TCP sockets
- Built-in HTTP/1.1 server implementation
- Built-in WebSocket support with standalone and upgrade modes
- HTTP over Unix Domain Sockets (UDS) support for super fast local IPC
- Zero-copy file transmission using `sendfile` (Linux) and `TransmitFile` (Windows)
- SIMD-accelerated parsing and formatting of HTTP messages
- Built on top of `epoll` (Linux), and `kqueue` (BSD, macOS), `IOCP` (Windows)
- Support for edge-triggered and level-triggered event notification
- Support for multiple event loops and multi-threaded applications

> [!NOTE]
> PowPow is experimental and under active development. The API may change without deprecation. If you are looking for a more stable and mature library, consider using [supranim](https://github.com/supranim/supranim) instead (based on LibEvent).

## Examples
...

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/openpeeps/powpow/issues)
- 👋 Wanna help? [Fork it!](https://github.com/openpeeps/powpow/fork)

### 🎩 License
LGPLv3 license. [Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright OpenPeeps & Contributors &mdash; All rights reserved.
