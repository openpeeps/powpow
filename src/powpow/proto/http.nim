# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | LGPL-v3 License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/powpow

## High-performance HTTP/1.1 request parser.
##
## Design goals:
##   - Incremental: feed bytes as they arrive from the socket
##   - Zero-copy: parse into byte offsets, materialize strings lazily
##   - Minimal allocations: only allocate when data is accessed
##   - Fast method dispatch: switch on first byte for O(1) method detection
##
## Uses std/httpcore types: HttpMethod, HttpCode, HttpHeaders, HttpVersion.

import std/[httpcore, strutils, oids, os]
import pkg/multipart

import ./simdscan
import ../net/tcp, ../loop

# ── Constants ────────────────────────────────────────────────────────────────

const
  MaxHeaderSize*  = 8192   ## Max header section size in bytes (default 8KB)
  MaxRequestLine* = 8192   ## Max request line size
  MaxHeaders*     = 100    ## Max number of headers
  DefaultBodyBuf* = 65536  ## Default body read buffer

  httpNewLine = "\r\n"
  headerSep   = "\r\n\r\n"

# ── Types ────────────────────────────────────────────────────────────────────

type
  HttpBodyCallback* = proc(data: openArray[byte]; done: bool) {.closure.}
    ## Callback invoked as body data arrives from the network.
    ## When set on an HttpParser, body bytes are streamed to this callback
    ## instead of being buffered in the parser. The callback receives raw
    ## (non-chunk-decoded) data for Content-Length bodies, or decoded data
    ## for chunked transfer encoding. `done` is true when this is the last
    ## body chunk.

  ParsePhase* = enum
    ## Parser state machine phases.
    PhaseRequestLine  ## Parsing the request line
    PhaseHeaders      ## Parsing header lines
    PhaseBody         ## Reading body (if Content-Length > 0)
    PhaseComplete     ## Request fully parsed
    PhaseError        ## Parse error occurred

  HttpParser* = ref object
    ## Incremental HTTP/1.1 request parser.
    buf:       seq[byte]       ## Accumulation buffer
    bufLen:    int              ## Current buffer length
    maxBodySize*: int64         ## Max body size (0 = unlimited)

    # Request line fields (byte offsets into buf)
    methodStr:  array[10, char] ## Raw method bytes (fast path)
    methodLen:  int
    pathStart:  int
    pathEnd:    int             ## End of path (before '?' or ' ')
    queryStart: int             ## -1 if no query
    queryEnd:   int
    httpMajor:  int
    httpMinor:  int

    # Header section
    headerEnd:  int             ## Byte offset past \r\n\r\n
    headerCount: int            ## Number of headers parsed
    contentLength: int          ## From Content-Length header (-1 if absent)
    transferChunked: bool       ## Transfer-Encoding: chunked
    connectionClose*: bool      ## Connection: close seen
    contentTypeStart: int       ## -1 if no Content-Type (lazy materialization)
    contentTypeLen: int

    # Chunked transfer encoding state
    chunkStart: int             ## Start of current chunk data
    chunkSize: int              ## Size of current chunk
    chunkParsed: int            ## Bytes parsed in current chunk
    bodyStart: int              ## Start of body data
    bodyLen: int                ## Total body length (for Content-Length)
    chunkBodyLen: int           ## Total decoded chunked body length

    # Streaming body callback
    onBodyData*: HttpBodyCallback ## Called as body bytes arrive (nil = buffered mode)
    bodyStreamed*: int64           ## Bytes streamed via callback so far
    streamingBody*: bool         ## true when body is being streamed to callback

    # Cached materialized values (filled during feed())
    methodCache*:  HttpMethod
    pathCache:     string
    queryCache:    string
    contentTypeVal: string

    phase:      ParsePhase
    errorCode:  HttpCode

  HttpRequest* = ref object
    ## A parsed HTTP request with lazy accessor methods.
    parser*:     HttpParser
    httpMethod*: HttpMethod
    conn*:       Connection
    streamer*:   MultipartStreamerRef
    streamPath*: string

    # Lazily materialized fields
    urlVal*:      string
    headersVal*:  HttpHeaders
    headersReady*: bool
    bodyVal*:     seq[byte]
    bodyReady*:   bool

  BodyStream* = object
    ## A stream for reading the request body in chunks.
    parser:  HttpParser
      # The parser's buffer is rearranged as body bytes are consumed, so the
      # BodyStream always reads from the start of the buffer (offset 0) and tracks
      # the current read position separately
    readPos: int
      # Current read offset, relative to headerEnd

# ── Fast method parser ───────────────────────────────────────────────────────

func parseMethod(buf: ptr UncheckedArray[byte], len: int): HttpMethod {.inline.} =
  # Parse HTTP method from raw bytes. Switch on first char for speed.
  if len == 0: return HttpGet  # default
  case char(buf[0])
  of 'G': HttpGet
  of 'P':
    if len >= 3 and char(buf[1]) == 'O': HttpPost
    elif len >= 3 and char(buf[1]) == 'U': HttpPut
    elif len >= 5 and char(buf[1]) == 'A': HttpPatch
    else: HttpPost  # fallback
  of 'D': HttpDelete
  of 'H': HttpHead
  of 'O': HttpOptions
  of 'C': HttpConnect
  of 'T': HttpTrace
  else:   HttpGet  # fallback for unknown methods

# ── Parser lifecycle ─────────────────────────────────────────────────────────

proc newHttpParser*(initialBufSize = 4096): HttpParser =
  ## Create a new HTTP request parser.
  HttpParser(
    buf:           newSeq[byte](initialBufSize),
    bufLen:        0,
    headerEnd:     -1,
    pathStart:     -1,
    queryStart:    -1,
    contentLength: -1,
    chunkStart:    0,
    chunkSize:     -1,
    chunkParsed:   0,
    bodyStart:     0,
    bodyLen:       0,
    chunkBodyLen:  0,
    maxBodySize:   0,
    methodCache:   HttpGet,
    pathCache:     "",
    queryCache:    "",
    contentTypeVal:"",
    contentTypeStart: -1,
    contentTypeLen: 0,
    phase:         PhaseRequestLine,
    errorCode:     Http200,
  )

proc reset*(p: HttpParser) =
  p.bufLen        = 0
  p.headerEnd     = -1
  p.methodLen     = 0
  p.pathStart     = -1
  p.pathEnd       = -1
  p.queryStart    = -1
  p.queryEnd      = -1
  p.httpMajor     = 1
  p.httpMinor     = 1
  p.headerEnd     = -1
  p.headerCount   = 0
  p.contentLength = -1
  p.transferChunked = false
  p.chunkStart    = 0
  p.chunkSize     = -1
  p.chunkParsed   = 0
  p.bodyStart     = 0
  p.bodyLen       = 0
  p.chunkBodyLen  = 0
  p.phase         = PhaseRequestLine
  p.errorCode     = Http200
  p.methodCache   = HttpGet
  p.pathCache.setLen(0)
  p.queryCache.setLen(0)
  p.contentTypeVal.setLen(0)
  p.contentTypeStart = -1
  p.contentTypeLen = 0
  if p.buf.len > 8192:
    p.buf.setLen(4096)

proc resetForNext*(p: HttpParser) =
  ## Reset the parser for the next pipelined request, preserving any
  ## unconsumed bytes in the buffer (e.g. bytes belonging to a subsequent
  ## request that arrived in the same TCP read).
  ##
  ## For streaming mode, the buffer has already been rearranged to contain
  ## only leftover bytes from the next request — no copy needed.
  let consumed = if p.streamingBody: 0  # buffer already contains only next-request bytes
                 elif p.transferChunked: p.headerEnd + p.chunkBodyLen
                 elif p.contentLength > 0: p.headerEnd + p.contentLength
                 else: p.headerEnd
  let leftover = p.bufLen - consumed

  if leftover > 0 and consumed >= 0:
    copyMem(addr p.buf[0], addr p.buf[consumed], leftover)

  p.bufLen        = max(leftover, 0)
  if p.buf.len > 8192:
    p.buf.setLen(4096)
  p.headerEnd     = -1
  p.methodLen     = 0
  p.pathStart     = -1
  p.pathEnd      = -1
  p.queryStart   = -1
  p.queryEnd     = -1
  p.httpMajor     = 1
  p.httpMinor     = 1
  p.headerCount   = 0
  p.contentLength = -1
  p.transferChunked = false
  p.connectionClose = false
  p.chunkStart    = 0
  p.chunkSize     = -1
  p.chunkParsed   = 0
  p.bodyStart     = 0
  p.bodyLen       = 0
  p.chunkBodyLen  = 0
  p.bodyStreamed  = 0
  p.streamingBody = false
  p.phase         = PhaseRequestLine
  p.errorCode     = Http200
  p.methodCache   = HttpGet
  p.pathCache.setLen(0)
  p.queryCache.setLen(0)
  p.contentTypeVal.setLen(0)
  p.contentTypeStart = -1
  p.contentTypeLen = 0

func phase*(p: HttpParser): ParsePhase {.inline.} = p.phase

# ── Internal: parse request line ─────────────────────────────────────────────

proc parseRequestLine(p: HttpParser): bool =
  ## Parse "METHOD /path?query HTTP/1.x\r\n" from the buffer.
  let buf = cast[ptr UncheckedArray[byte]](addr p.buf[0])
  let crlf = findCRLF(buf, 0, p.bufLen)
  if crlf < 0:
    if p.bufLen > MaxRequestLine:
      p.phase = PhaseError
      p.errorCode = Http414  # URI Too Long
      return false
    return false  # need more data

  # Parse method
  var i = 0
  while i < crlf and char(buf[i]) != ' ':
    if i >= 10:
      p.phase = PhaseError
      p.errorCode = Http400
      return false
    p.methodStr[i] = char(buf[i])
    inc i
  p.methodLen = i

  if i >= crlf:
    p.phase = PhaseError
    p.errorCode = Http400
    return false
  inc i  # skip space

  # Parse path (and optional query)
  p.pathStart = i
  p.pathEnd = i
  p.queryStart = -1
  p.queryEnd = -1
  while i < crlf and char(buf[i]) != ' ':
    if char(buf[i]) == '?' and p.queryStart < 0:
      p.pathEnd = i
      p.queryStart = i + 1
    inc i
  if p.queryStart >= 0:
    p.queryEnd = i
  else:
    p.pathEnd = i

  p.methodCache = parseMethod(cast[ptr UncheckedArray[byte]](addr p.buf[0]), p.methodLen)

  if i >= crlf:
    p.phase = PhaseError
    p.errorCode = Http400
    return false
  inc i  # skip space

  # Parse HTTP version: "HTTP/x.y"
  if i + 8 > crlf or
     char(buf[i]) != 'H' or char(buf[i+1]) != 'T' or char(buf[i+2]) != 'T' or
     char(buf[i+3]) != 'P' or char(buf[i+4]) != '/':
    p.phase = PhaseError
    p.errorCode = Http400
    return false
  p.httpMajor = int(char(buf[i+5])) - ord('0')
  p.httpMinor = int(char(buf[i+7])) - ord('0')

  # Advance past the request line \r\n
  p.phase = PhaseHeaders
  return true

# ── Internal: scan headers ───────────────────────────────────────────────────

proc scanHeaders(p: HttpParser): bool =
  ## Scan header section for \r\n\r\n. Extract Content-Length and Transfer-Encoding
  ## during the scan. Header values are NOT materialized yet (lazy).
  let sepEnd = findDoubleCRLF(cast[ptr UncheckedArray[byte]](addr p.buf[0]),
                               0, p.bufLen)
  if sepEnd < 0:
    if p.bufLen > MaxHeaderSize:
      p.phase = PhaseError
      p.errorCode = Http431  # Request Header Fields Too Large
      return false
    return false  # need more data

  p.headerEnd = sepEnd

  # Quick scan for Content-Length and Transfer-Encoding
  let buf = cast[ptr UncheckedArray[byte]](addr p.buf[0])
  var i = 0
  var lineStart = 0

  # Skip request line
  while i < sepEnd - 3:
    if char(buf[i]) == '\r' and char(buf[i+1]) == '\n':
      i += 2
      lineStart = i
      break
    inc i

  # Scan header lines
  while i < sepEnd - 1:
    if char(buf[i]) == '\r' and char(buf[i+1]) == '\n':
      # Process header line from lineStart to i
      let lineLen = i - lineStart
      if lineLen > 0:
        inc p.headerCount
        if p.headerCount > MaxHeaders:
          p.phase = PhaseError
          p.errorCode = Http431
          return false

        # Quick check for Content-Length (case-insensitive prefix match)
        var matched = false
        if lineLen >= 15:
          let c = char(buf[lineStart])
          if c == 'C' or c == 'c':
            var isCL = true
            const clKey = "content-length:"
            if lineLen >= clKey.len:
              for j in 0 ..< clKey.len:
                let ch = char(buf[lineStart + j])
                if ch != clKey[j] and ch != (char(ord(clKey[j]) xor 32)):
                  isCL = false
                  break
            if isCL:
              matched = true
              var valStart = lineStart + clKey.len
              while valStart < i and char(buf[valStart]) == ' ':
                inc valStart
              if valStart < i and char(buf[valStart]) == '-':
                p.phase = PhaseError
                p.errorCode = Http400
                return false
              var num = 0
              var j = valStart
              while j < i and char(buf[j]) in '0'..'9':
                if num > high(int) div 10:
                  p.phase = PhaseError
                  p.errorCode = Http413
                  return false
                num = num * 10 + (ord(char(buf[j])) - ord('0'))
                inc j
              if j == valStart:
                p.phase = PhaseError
                p.errorCode = Http400
                return false
              if p.maxBodySize > 0 and num > p.maxBodySize:
                p.phase = PhaseError
                p.errorCode = Http413
                return false
              if p.contentLength >= 0 and p.contentLength != num:
                p.phase = PhaseError
                p.errorCode = Http400
                return false
              p.contentLength = num

        # Quick check for Transfer-Encoding
        if not matched and lineLen >= 19:
          let c = char(buf[lineStart])
          if c == 'T' or c == 't':
            var isTE = true
            const teKey = "transfer-encoding:"
            if lineLen >= teKey.len:
              for j in 0 ..< teKey.len:
                let ch = char(buf[lineStart + j])
                if ch != teKey[j] and ch != (char(ord(teKey[j]) xor 32)):
                  isTE = false
                  break
              if isTE:
                matched = true
                var valStart = lineStart + teKey.len
                while valStart < i and char(buf[valStart]) == ' ':
                  inc valStart
                if i - valStart >= 7:
                  p.transferChunked = true

        # Quick check for Connection: close
        if not matched and lineLen >= 12:
          let c = char(buf[lineStart])
          if c == 'C' or c == 'c':
            var isCon = true
            const conKey = "connection:"
            if lineLen >= conKey.len:
              for j in 0 ..< conKey.len:
                let ch = char(buf[lineStart + j])
                if ch != conKey[j] and ch != (char(ord(conKey[j]) xor 32)):
                  isCon = false
                  break
              if isCon:
                matched = true
                var valStart = lineStart + conKey.len
                while valStart < i and char(buf[valStart]) == ' ':
                  inc valStart
                let valLen = i - valStart
                const closeKey = "close"
                if valLen >= closeKey.len:
                  var isClose = true
                  for j in 0 ..< closeKey.len:
                    let ch = char(buf[valStart + j])
                    if ch != closeKey[j] and ch != (char(ord(closeKey[j]) xor 32)):
                      isClose = false
                      break
                  if isClose:
                    p.connectionClose = true

        # Quick check for Content-Type
        if lineLen >= 14:
          let c = char(buf[lineStart])
          if c == 'C' or c == 'c':
            const ctKey = "content-type:"
            if lineLen >= ctKey.len:
              var isCT = true
              for j in 0 ..< ctKey.len:
                let ch = char(buf[lineStart + j])
                if ch != ctKey[j] and ch != (char(ord(ctKey[j]) xor 32)):
                  isCT = false
                  break
              if isCT:
                var valStart = lineStart + ctKey.len
                while valStart < i and char(buf[valStart]) == ' ':
                  inc valStart
                let valLen = i - valStart
                if valLen > 0:
                  p.contentTypeStart = valStart
                  p.contentTypeLen = valLen

        inc i  # skip \r
      inc i  # skip \n
      lineStart = i
    else:
      inc i

  # Determine body presence
  if p.contentLength > 0 or p.transferChunked:
    p.phase = PhaseBody
  else:
    p.phase = PhaseComplete

  return true

# ── Feed bytes ───────────────────────────────────────────────────────────────

proc ensureCapacity(p: HttpParser, needed: int) {.inline.} =
  if p.bufLen + needed > p.buf.len:
    let newCap = max(p.buf.len * 2, p.bufLen + needed)
    p.buf.setLen(newCap)

proc parseChunkSize(buf: ptr UncheckedArray[byte], start, maxLen: int): int {.inline.} =
  ## Parse hexadecimal chunk size. Returns -1 on error, -2 if incomplete.
  ## Handles chunk extensions (e.g., "5;ext=value").
  var i = start
  var size = 0
  var foundDigit = false

  while i < maxLen:
    let c = char(buf[i])
    case c
    of '0'..'9':
      if size > high(int) div 16:
        return -1
      size = size * 16 + (ord(c) - ord('0'))
      foundDigit = true
    of 'a'..'f':
      if size > high(int) div 16:
        return -1
      size = size * 16 + (ord(c) - ord('a') + 10)
      foundDigit = true
    of 'A'..'F':
      if size > high(int) div 16:
        return -1
      size = size * 16 + (ord(c) - ord('A') + 10)
      foundDigit = true
    of ';', ' ':
      # Chunk extension - skip until CRLF
      while i < maxLen:
        if char(buf[i]) == '\r':
          if i + 1 < maxLen and char(buf[i + 1]) == '\n':
            if foundDigit:
              return size
            return -1
          return -2
        inc i
      return -2
    of '\r':
      if i + 1 < maxLen and char(buf[i + 1]) == '\n':
        if foundDigit:
          return size
        return -1
      return -2
    else:
      return -1
    inc i

  if not foundDigit:
    return -1
  return -2

proc parseChunkedBody(p: HttpParser): bool =
  ## Parse chunked transfer encoding. Returns true when complete.
  let buf = cast[ptr UncheckedArray[byte]](addr p.buf[0])
  var pos = p.bodyStart

  while pos < p.bufLen:
    # Check if this is the last chunk (size 0)
    if p.chunkSize == 0:
      # After the last chunk, we expect optional trailers followed by CRLF
      # For simplicity, just look for CRLF to indicate end of chunked body
      # (trailers are rare in practice and can be handled later if needed)
      if pos < p.bufLen and char(buf[pos]) == '\r':
        if pos + 1 < p.bufLen and char(buf[pos + 1]) == '\n':
          p.phase = PhaseComplete
          return true
        else:
          # Incomplete - need more data
          p.bodyStart = pos
          return false
      elif pos < p.bufLen and char(buf[pos]) == '\n':
        # Handle LF-only line ending
        p.phase = PhaseComplete
        return true
      else:
        # Incomplete - need more data
        p.bodyStart = pos
        return false

    # Need at least chunk size + CRLF
    if p.chunkSize < 0:
      # Parse chunk size
      let sizeEnd = findCRLF(buf, pos, p.bufLen)
      if sizeEnd < 0:
        # Incomplete - need more data
        if p.bufLen - pos > 16:  # Max chunk size line length
          p.phase = PhaseError
          p.errorCode = Http400
          return false
        p.bodyStart = pos
        return false

      # Parse chunk size - pass sizeEnd + 2 to include the CRLF
      let chunkSize = parseChunkSize(buf, pos, sizeEnd + 2)
      if chunkSize == -1:
        p.phase = PhaseError
        p.errorCode = Http400
        return false
      if chunkSize == -2:
        p.bodyStart = pos
        return false

      if p.maxBodySize > 0 and (p.chunkBodyLen + chunkSize) > p.maxBodySize:
        p.phase = PhaseError
        p.errorCode = Http413
        return false

      p.chunkSize = chunkSize
      p.chunkParsed = 0
      pos = sizeEnd + 2  # Skip CRLF

      # If this is the last chunk, continue to the next iteration to handle it
      if p.chunkSize == 0:
        continue

    # Read chunk data - make sure we're still within buffer
    if pos >= p.bufLen:
      p.bodyStart = pos
      return false  # Need more data

    let remaining = p.chunkSize - p.chunkParsed
    let available = p.bufLen - pos

    if available >= remaining:
      # Have enough data for this chunk
      # Copy chunk data to body buffer
      let oldBodyLen = p.chunkBodyLen
      p.chunkBodyLen += remaining

      # Ensure body buffer capacity
      if p.buf.len < p.headerEnd + p.chunkBodyLen:
        let newCap = max(p.buf.len * 2, p.headerEnd + p.chunkBodyLen)
        var newBuf = newSeq[byte](newCap)
        if p.bufLen > 0:
          copyMem(addr newBuf[0], addr p.buf[0], p.bufLen)
        p.buf = newBuf

      # Copy chunk data to body area
      if remaining > 0:
        copyMem(addr p.buf[p.headerEnd + oldBodyLen], addr buf[pos], remaining)

      pos += remaining
      p.chunkParsed = p.chunkSize

      # Expect CRLF after chunk data - need at least 2 more bytes
      if pos + 1 < p.bufLen and char(buf[pos]) == '\r' and char(buf[pos + 1]) == '\n':
        pos += 2
        p.chunkSize = -1  # Ready for next chunk
        p.chunkParsed = 0
      elif pos >= p.bufLen or (pos + 1 >= p.bufLen):
        # Incomplete - need more data for CRLF
        p.bodyStart = pos
        return false
      else:
        p.phase = PhaseError
        p.errorCode = Http400
        return false
    else:
      # Partial chunk - copy what we have
      if available > 0:
        let oldBodyLen = p.chunkBodyLen
        p.chunkBodyLen += available

        # Ensure body buffer capacity
        if p.buf.len < p.headerEnd + p.chunkBodyLen:
          let newCap = max(p.buf.len * 2, p.headerEnd + p.chunkBodyLen)
          var newBuf = newSeq[byte](newCap)
          if p.bufLen > 0:
            copyMem(addr newBuf[0], addr p.buf[0], p.bufLen)
          p.buf = newBuf

        # Copy partial chunk data
        copyMem(addr p.buf[p.headerEnd + oldBodyLen], addr buf[pos], available)

        p.chunkParsed += available
      pos = p.bufLen
      p.bodyStart = pos
      return false  # Need more data

  p.bodyStart = pos
  return false  # Need more data

proc feed*(p: HttpParser, data: openArray[byte]): ParsePhase {.discardable.} =
  ## Feed raw bytes from the network into the parser.
  ## Returns the current parse phase after processing.
  ##
  ## Keep calling `feed()` as data arrives. When the return value is
  ## `PhaseComplete`, the request is ready. `PhaseError` means bad request.
  ##
  ## If `onBodyData` is set, body bytes are streamed to the callback
  ## instead of being buffered in `p.buf`. This dramatically reduces
  ## memory for large uploads since `p.buf` only needs to hold headers.
  if p.phase == PhaseComplete or p.phase == PhaseError:
    return p.phase

  # Streaming mode: after headers are parsed, body bytes go to callback
  if p.streamingBody and p.phase == PhaseBody:
    if p.transferChunked:
      # Chunked streaming: forward all data; chunk boundaries handle splitting
      if data.len > 0 and p.onBodyData != nil:
        p.onBodyData(data, false)
      return p.phase
    # Content-Length streaming: only forward body bytes, buffer leftover for next request
    let remaining = p.contentLength - p.bodyStreamed
    if remaining <= 0:
      p.bodyLen = p.contentLength
      p.phase = PhaseComplete
      return p.phase
    let bodyBytes = min(data.len, remaining)
    if bodyBytes > 0 and p.onBodyData != nil:
      p.onBodyData(data.toOpenArray(0, bodyBytes - 1), bodyBytes >= remaining)
    p.bodyStreamed += bodyBytes
    if p.bodyStreamed >= p.contentLength:
      p.bodyLen = p.contentLength
      p.phase = PhaseComplete
    # Buffer any leftover bytes for the next pipelined request
    let leftover = data.len - bodyBytes
    if leftover > 0:
      p.ensureCapacity(leftover)
      copyMem(addr p.buf[p.bufLen], unsafeAddr data[bodyBytes], leftover)
      p.bufLen += leftover
    return p.phase

  p.ensureCapacity(data.len)
  if data.len > 0:
    copyMem(addr p.buf[p.bufLen], unsafeAddr data[0], data.len)
    p.bufLen += data.len

  # State machine advancement
  if p.phase == PhaseRequestLine:
    if not p.parseRequestLine():
      return p.phase

  if p.phase == PhaseHeaders:
    if not p.scanHeaders():
      return p.phase

  if p.phase == PhaseBody:
    if p.onBodyData != nil and not p.streamingBody:
      # Activate streaming mode instead of buffering the body.
      # This must happen before the buffered body completion check
      # so that even a fully-arrived body is streamed via callback.
      p.streamingBody = true
      let bodyStart = p.headerEnd
      let bodyInBuf = p.bufLen - bodyStart
      if bodyInBuf > 0:
        let bytesToStream = if not p.transferChunked and p.contentLength > 0:
                              min(bodyInBuf, p.contentLength)
                            else:
                              bodyInBuf
        if bytesToStream > 0:
          let doneAfter = not p.transferChunked and p.contentLength > 0 and p.bodyStreamed + bytesToStream >= p.contentLength
          p.onBodyData(p.buf.toOpenArray(bodyStart, bodyStart + bytesToStream - 1), doneAfter)
        p.bodyStreamed = bytesToStream
        # Move leftover bytes (from next pipelined request) to start of buffer
        let leftoverStart = bodyStart + bytesToStream
        let leftover = p.bufLen - leftoverStart
        if leftover > 0:
          copyMem(addr p.buf[0], addr p.buf[leftoverStart], leftover)
          p.bufLen = leftover
        else:
          p.bufLen = 0
      else:
        p.bufLen = 0
      # For Content-Length, check if we already have all the body
      if not p.transferChunked and p.contentLength > 0:
        if p.bodyStreamed >= p.contentLength:
          p.bodyLen = p.contentLength
          p.phase = PhaseComplete
      return p.phase

    if p.transferChunked:
      # Chunked transfer encoding
      if p.bodyStart == 0:
        p.bodyStart = p.headerEnd
      if p.parseChunkedBody():
        p.phase = PhaseComplete
    else:
      # Content-Length based
      let expected = p.headerEnd + p.contentLength
      if p.bufLen >= expected:
        p.bodyLen = p.contentLength
        p.phase = PhaseComplete

  return p.phase

proc feed*(p: HttpParser, data: string): ParsePhase {.inline, discardable.} =
  ## Convenience overload for feeding string data.
  p.feed(data.toOpenArrayByte(0, data.high))

proc tryAdvance*(p: HttpParser) =
  ## Advance the parser state machine using existing buffer data.
  ## Equivalent to `feed(@[])` but without allocating an empty seq.
  ## Used after `resetForNext()` to process pipelined request bytes.
  if p.phase in {PhaseComplete, PhaseError}: return
  if p.phase == PhaseRequestLine:
    if not p.parseRequestLine(): return
  if p.phase == PhaseHeaders:
    if not p.scanHeaders(): return
  if p.phase == PhaseBody:
    if p.onBodyData != nil and not p.streamingBody:
      p.streamingBody = true
      let bodyStart = p.headerEnd
      let bodyInBuf = p.bufLen - bodyStart
      if bodyInBuf > 0:
        let bytesToStream = if not p.transferChunked and p.contentLength > 0:
                              min(bodyInBuf, p.contentLength)
                            else:
                              bodyInBuf
        if bytesToStream > 0 and p.onBodyData != nil:
          let doneAfter = not p.transferChunked and p.contentLength > 0 and p.bodyStreamed + bytesToStream >= p.contentLength
          p.onBodyData(p.buf.toOpenArray(bodyStart, bodyStart + bytesToStream - 1), doneAfter)
        p.bodyStreamed = bytesToStream
        let leftoverStart = bodyStart + bytesToStream
        let leftover = p.bufLen - leftoverStart
        if leftover > 0:
          copyMem(addr p.buf[0], addr p.buf[leftoverStart], leftover)
          p.bufLen = leftover
        else:
          p.bufLen = 0
      else:
        p.bufLen = 0
      if not p.transferChunked and p.contentLength > 0:
        if p.bodyStreamed >= p.contentLength:
          p.bodyLen = p.contentLength
          p.phase = PhaseComplete
      return
    if p.transferChunked:
      if p.bodyStart == 0:
        p.bodyStart = p.headerEnd
      if p.parseChunkedBody():
        p.phase = PhaseComplete
    elif p.contentLength > 0:
      let expected = p.headerEnd + p.contentLength
      if p.bufLen >= expected:
        p.bodyLen = p.contentLength
        p.phase = PhaseComplete

func isComplete*(p: HttpParser): bool {.inline.} =
  p.phase == PhaseComplete

func isError*(p: HttpParser): bool {.inline.} =
  p.phase == PhaseError

func error*(p: HttpParser): HttpCode {.inline.} =
  p.errorCode

# ── Peek accessors (available during PhaseBody) ────────────────────────────────

func peekMethod*(p: HttpParser): HttpMethod {.inline.} =
  p.methodCache

proc peekPath*(p: HttpParser): lent string {.inline.} =
  if p.pathCache.len == 0 and p.pathEnd > p.pathStart:
    let buf = cast[ptr UncheckedArray[byte]](addr p.buf[0])
    let plen = p.pathEnd - p.pathStart
    p.pathCache = newString(plen)
    copyMem(addr p.pathCache[0], addr buf[p.pathStart], plen)
  p.pathCache

proc peekContentType*(p: HttpParser): lent string {.inline.} =
  if p.contentTypeVal.len == 0 and p.contentTypeStart >= 0:
    let buf = cast[ptr UncheckedArray[byte]](addr p.buf[0])
    p.contentTypeVal = newString(p.contentTypeLen)
    copyMem(addr p.contentTypeVal[0], addr buf[p.contentTypeStart], p.contentTypeLen)
  p.contentTypeVal

# ── HttpRequest: lazy accessors ──────────────────────────────────────────────

proc getRequest*(p: HttpParser): HttpRequest =
  assert p.phase == PhaseComplete
  result = HttpRequest(
    parser:     p,
    httpMethod: p.methodCache,
    headersReady: false,
    bodyReady:  false,
  )

proc getMethod*(req: HttpRequest): HttpMethod {.inline.} =
  req.httpMethod

proc getPath*(req: HttpRequest): lent string =
  let p = req.parser
  if p.pathCache.len == 0 and p.pathEnd > p.pathStart:
    let buf = cast[ptr UncheckedArray[byte]](addr p.buf[0])
    let plen = p.pathEnd - p.pathStart
    p.pathCache = newString(plen)
    copyMem(addr p.pathCache[0], addr buf[p.pathStart], plen)
  p.pathCache

proc getQuery*(req: HttpRequest): lent string =
  let p = req.parser
  if p.queryCache.len == 0 and p.queryStart >= 0:
    let buf = cast[ptr UncheckedArray[byte]](addr p.buf[0])
    let qlen = p.queryEnd - p.queryStart
    p.queryCache = newString(qlen)
    copyMem(addr p.queryCache[0], addr buf[p.queryStart], qlen)
  p.queryCache

proc getUrl*(req: HttpRequest): lent string =
  if req.urlVal.len == 0:
    let path = req.getPath()
    let query = req.getQuery()
    req.urlVal = if query.len > 0: path & "?" & query else: path
  req.urlVal

proc getHeaders*(req: HttpRequest): HttpHeaders =
  if not req.headersReady:
    let p = req.parser
    let buf = cast[ptr UncheckedArray[byte]](addr p.buf[0])
    req.headersVal = newHttpHeaders()
    var i = 0
    # Skip request line
    while i < p.headerEnd - 1:
      if char(buf[i]) == '\r' and char(buf[i+1]) == '\n':
        i += 2
        break
      inc i
    # Parse headers — scan for colon directly in buffer, avoid intermediate line string
    while i < p.headerEnd - 1:
      if char(buf[i]) == '\r' and char(buf[i+1]) == '\n':
        inc i, 2
        continue
      let lineStart = i
      while i < p.headerEnd - 1:
        if char(buf[i]) == '\r':
          break
        inc i
      let lineLen = i - lineStart
      if lineLen > 0:
        var colonPos = lineStart
        while colonPos < i and char(buf[colonPos]) != ':':
          inc colonPos
        if colonPos < i and colonPos > lineStart:
          let keyLen = colonPos - lineStart
          var key = newString(keyLen)
          copyMem(addr key[0], addr buf[lineStart], keyLen)
          var valStart = colonPos + 1
          while valStart < i and char(buf[valStart]) == ' ':
            inc valStart
          let valLen = i - valStart
          if valLen > 0:
            var value = newString(valLen)
            copyMem(addr value[0], addr buf[valStart], valLen)
            req.headersVal.add(key, value)
          else:
            req.headersVal.add(key, "")
      if i < p.headerEnd - 1 and char(buf[i]) == '\r':
        inc i
      inc i
    req.headersReady = true
  return req.headersVal

func getContentLength*(req: HttpRequest): int {.inline.} =
  req.parser.contentLength

func getConnectionClose*(req: HttpRequest): bool {.inline.} =
  req.parser.connectionClose

proc getClientIp*(req: HttpRequest): string {.inline.} =
  if req.conn != nil: req.conn.getClientIp() else: ""

proc getBody*(req: HttpRequest): seq[byte] =
  ## Get the request body. Returns empty seq if no body.
  if not req.bodyReady:
    let p = req.parser
    if p.transferChunked and p.chunkBodyLen > 0:
      # Chunked body - already decoded into buffer
      req.bodyVal = newSeq[byte](p.chunkBodyLen)
      copyMem(addr req.bodyVal[0],
              addr p.buf[p.headerEnd], p.chunkBodyLen)
    elif p.contentLength > 0 and p.bufLen >= p.headerEnd + p.contentLength:
      # Content-Length body
      req.bodyVal = newSeq[byte](p.contentLength)
      copyMem(addr req.bodyVal[0],
              addr p.buf[p.headerEnd], p.contentLength)
    else:
      req.bodyVal = @[]
    req.bodyReady = true
  return req.bodyVal

proc getBodyString*(req: HttpRequest): string =
  ## Get the request body as a string.
  let body = req.getBody()
  if body.len == 0: return ""
  result = newString(body.len)
  copyMem(addr result[0], unsafeAddr body[0], body.len)

# ── Body streaming ────────────────────────────────────────────────────────────

template bodyLen(p: HttpParser): int =
  if p.transferChunked: p.chunkBodyLen
  elif p.contentLength > 0: p.contentLength
  else: 0

proc getBodyStream*(req: HttpRequest): BodyStream =
  ## Returns a BodyStream for reading the request body in chunks.
  result.parser = req.parser
  result.readPos = 0

proc readChunk*(stream: var BodyStream; maxLen: Natural): seq[byte] =
  ## Reads up to maxLen bytes from the body stream.
  ## Returns empty seq when no more data is available.
  let p = stream.parser
  let blen = bodyLen(p)
  let available = blen - stream.readPos
  if available <= 0: return @[]
  let toRead = min(available, maxLen)
  result = newSeq[byte](toRead)
  if toRead > 0:
    let src = cast[ptr UncheckedArray[byte]](addr p.buf[p.headerEnd + stream.readPos])
    copyMem(addr result[0], src, toRead)
    stream.readPos += toRead

proc readChunkString*(stream: var BodyStream; maxLen: Natural): string =
  ## Reads up to maxLen bytes from the body stream as a string.
  let p = stream.parser
  let blen = bodyLen(p)
  let available = blen - stream.readPos
  if available <= 0: return ""
  let toRead = min(available, maxLen)
  result = newString(toRead)
  if toRead > 0:
    let src = cast[ptr UncheckedArray[byte]](addr p.buf[p.headerEnd + stream.readPos])
    copyMem(addr result[0], src, toRead)
    stream.readPos += toRead

proc peekChunk*(stream: var BodyStream; maxLen: Natural): tuple[data: ptr UncheckedArray[byte]; len: int] =
  ## Returns a pointer and length to the next available chunk (up to maxLen).
  ## No copy is performed. The pointer is only valid until the next buffer operation.
  let p = stream.parser
  let blen = bodyLen(p)
  let available = blen - stream.readPos
  if available <= 0: return (nil, 0)
  let toRead = min(available, maxLen)
  result = (cast[ptr UncheckedArray[byte]](addr p.buf[p.headerEnd + stream.readPos]), toRead)

proc drainChunk*(stream: var BodyStream; len: Natural) {.inline.} =
  let p = stream.parser
  let blen = bodyLen(p)
  let available = blen - stream.readPos
  stream.readPos += min(len, available)

proc readChunkInto*(stream: var BodyStream; buf: var seq[byte]; maxLen: Natural): int =
  ## Reads up to maxLen bytes into a pre-allocated buffer.
  ## Returns the number of bytes written (0 = EOF).
  ## The caller can reuse `buf` across calls — no per-chunk allocation.
  let p = stream.parser
  let blen = bodyLen(p)
  let available = blen - stream.readPos
  if available <= 0: return 0
  let toRead = min(available, maxLen)
  buf.setLen(toRead)
  if toRead > 0:
    let src = cast[ptr UncheckedArray[byte]](addr p.buf[p.headerEnd + stream.readPos])
    copyMem(addr buf[0], src, toRead)
    stream.readPos += toRead
  result = toRead

proc peekAll*(stream: BodyStream): tuple[data: ptr UncheckedArray[byte]; len: int] =
  ## Zero-copy view of the entire remaining body. No allocation.
  ## The pointer is valid for the duration of the request handler.
  let p = stream.parser
  let blen = bodyLen(p)
  let remaining = blen - stream.readPos
  if remaining <= 0: return (nil, 0)
  result = (cast[ptr UncheckedArray[byte]](addr p.buf[p.headerEnd + stream.readPos]), remaining)

# ── Zero-copy body view ───────────────────────────────────────────────────────

proc getBodyView*(p: HttpParser): tuple[data: ptr UncheckedArray[byte]; len: int] =
  ## Zero-copy pointer into the parser buffer for the entire body.
  ## No allocation. The pointer is valid until `feed()` is called again.
  ##
  ## For Content-Length bodies: points to p.buf[p.headerEnd], len = contentLength.
  ## For chunked bodies: points to decoded data in p.buf[p.headerEnd], len = chunkBodyLen.
  ## Returns (nil, 0) if no body is present.
  if p.transferChunked and p.chunkBodyLen > 0:
    result = (cast[ptr UncheckedArray[byte]](addr p.buf[p.headerEnd]), p.chunkBodyLen)
  elif p.contentLength > 0 and p.bufLen >= p.headerEnd + p.contentLength:
    result = (cast[ptr UncheckedArray[byte]](addr p.buf[p.headerEnd]), p.contentLength)
  else:
    result = (nil, 0)

proc bodyView*(req: HttpRequest): tuple[data: ptr UncheckedArray[byte]; len: int] =
  ## Zero-copy pointer into the parser buffer for the entire body.
  ## No allocation. The pointer is valid for the duration of the request handler.
  req.parser.getBodyView()

# ── Lazy multipart accessor ────────────────────────────────────────────────────

proc getMultipart*(req: HttpRequest; tmpDir = ""): MultipartStreamerRef =
  ## Lazily parse multipart/form-data from the request body on first call.
  ## Returns a `MultipartStreamerRef` with parsed boundaries, or nil if
  ## the Content-Type is not multipart/form-data.
  ##
  ## Uses `bodyView()` internally for zero-copy access to the parser buffer.
  ## Feeds in 64KB chunks for lightweight per-chunk processing (magic number
  ## checking, file writes, etc). For streaming routes (auto-detected multipart
  ## Content-Type), the parser buffer is bypassed entirely and `req.streamer`
  ## is pre-populated — returns immediately with zero additional work.
  ##
  ## Memory (lazy, already-buffered body): parser buffer + 64KB write buffer.
  ## Memory (streaming, auto-detected): ~4KB headers + 64KB write buffer.
  ##
  ## Usage:
  ##   let mp = req.getMultipart()
  ##   if mp != nil and mp.isComplete():
  ##     for b in mp.boundaries(): ...
  ##     mp.cleanup()
  if req.streamer != nil:
    return req.streamer
  let headers = req.getHeaders()
  let ct = headers.getOrDefault("Content-Type", @[""].HttpHeaderValues)
  if not string(ct).startsWith("multipart/form-data"):
    return nil
  var ms = newMultipartStreamerRef(string(ct), tmpDir = tmpDir)
  let (data, totalLen) = req.bodyView()
  if totalLen > 0 and data != nil:
    const ChunkSize = 65536
    var pos = 0
    while pos < totalLen:
      let chunkLen = min(ChunkSize, totalLen - pos)
      let chunk = cast[ptr UncheckedArray[byte]](cast[int](data) + pos)
      ms[].feed(chunk, chunkLen)
      pos += chunkLen
  req.streamer = ms
  return ms

# ── Stream raw body to file (on-demand) ────────────────────────────────────

proc streamToFile*(req: HttpRequest; tmpDir = ""): string =
  ## Stream the request body (or re-stream from buffer) to a temp file.
  ## Returns the temp file path. The caller should delete the file when done.
  ##
  ## If the route uses `streamToFile = true`, the body was already streamed
  ## and this just returns `req.streamPath`. Otherwise, it feeds body bytes
  ## from the parser buffer to a temp file in 64KB chunks — zero extra copies
  ## beyond the one already in the parser buffer.
  ##
  ## Usage:
  ##   let path = req.streamToFile()
  ##   defer: removeFile(path)
  ##   # process path...
  if req.streamPath.len > 0:
    return req.streamPath
  let (data, totalLen) = req.parser.getBodyView()
  if totalLen == 0 or data == nil:
    return ""
  let dir = if tmpDir.len > 0: tmpDir else: getTempDir()
  discard existsOrCreateDir(dir)
  let filePath = dir / $genOid()
  var f = open(filePath, fmWrite)
  defer: f.close()
  const StreamChunk = 65536
  var pos = 0
  while pos < totalLen:
    let chunkLen = min(StreamChunk, totalLen - pos)
    let src = cast[ptr UncheckedArray[byte]](cast[int](data) + pos)
    discard f.writeBuffer(cast[pointer](src), chunkLen)
    pos += chunkLen
  req.streamPath = filePath
  return filePath

func headerBytes*(req: HttpRequest): int {.inline.} =
  req.parser.headerEnd

proc getRemainingData*(p: HttpParser): seq[byte] =
  ## Return any unconsumed bytes after the HTTP headers (and body, if present).
  ## Useful after an HTTP/1.1 upgrade (e.g. WebSocket) where extra bytes
  ## from the initial TCP read may contain the first protocol frames.
  let consumed = if p.transferChunked: p.headerEnd + p.chunkBodyLen
                 elif p.contentLength > 0: p.headerEnd + p.contentLength
                 else: p.headerEnd
  let leftover = p.bufLen - consumed
  if leftover > 0:
    result = newSeq[byte](leftover)
    copyMem(addr result[0], unsafeAddr p.buf[consumed], leftover)
  else:
    result = @[]
