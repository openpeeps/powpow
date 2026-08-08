# A high-performance, event notification library for Nim.
#
# (c) 2026 George Lemon | MIT License
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
  HeaderBufCap    = MaxRequestLine + MaxHeaderSize  ## feed()-time bound on the
    ## header-section buffer: a single oversized packet must be rejected (414/431)
    ## BEFORE ensureCapacity grows the buffer to its size.
  MaxStreamBodySize* = 512 * 1024 * 1024  ## Absolute cap for streamed bodies
    ## (onBodyData) when maxBodySize == 0: a hostile client can't drive
    ## unbounded disk/RAM via a streaming upload.

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
    buf*:      seq[byte]       ## Accumulation buffer
    bufLen*:   int              ## Current buffer length
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
    headerEnd*: int             ## Byte offset past \r\n\r\n
    headerCount: int            ## Number of headers parsed
    contentLength*: int          ## From Content-Length header (-1 if absent)
    transferEncoded: bool       ## Any Transfer-Encoding header present
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

    # Expect: 100-continue
    expectContinue*: bool         ## Client sent Expect: 100-continue

    # Streaming body callback
    onBodyData*: HttpBodyCallback ## Called as body bytes arrive (nil = buffered mode)
    bodyStreamed*: int64           ## Bytes streamed via callback so far
    streamingBody*: bool         ## true when body is being streamed to callback

    # Cached materialized values (filled during feed())
    methodCache*:  HttpMethod
    pathCache:     string
    queryCache:    string
    contentTypeVal: string

    phase*:     ParsePhase
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

func contentEnd(p: HttpParser): int {.inline.} =
  ## Byte offset just past the Content-Length body. Saturates at high(int)
  ## instead of overflowing when contentLength is near high(int) — a hostile
  ## `Content-Length: 9223372036854775808` header must not crash the parser.
  if p.contentLength > high(int) - p.headerEnd:
    high(int)
  else:
    p.headerEnd + p.contentLength

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
    expectContinue: false,
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
  p.transferEncoded = false
  p.transferChunked = false
  p.connectionClose = false
  p.expectContinue = false
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
                 elif p.transferChunked: p.bodyStart  # past the final CRLF (set by parseChunkedBody)
                 elif p.contentLength > 0: p.contentEnd
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
  p.transferEncoded = false
  p.transferChunked = false
  p.connectionClose = false
  p.expectContinue = false
  p.chunkStart    = 0
  p.chunkSize     = -1
  p.chunkParsed   = 0
  p.bodyStart     = 0
  p.bodyLen       = 0
  p.chunkBodyLen  = 0
  p.bodyStreamed  = 0
  p.streamingBody = false
  p.expectContinue = false
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
        # Reject obs-fold / leading-whitespace header lines (RFC 7230 §3.2.4):
        # a header whose name begins with SP/HTAB is a smuggling/parsing hazard.
        let lc = char(buf[lineStart])
        if lc == ' ' or lc == '\t':
          p.phase = PhaseError
          p.errorCode = Http400
          return false
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
              while valStart < i and (char(buf[valStart]) == ' ' or char(buf[valStart]) == '\t'):
                inc valStart
              if valStart < i and char(buf[valStart]) == '-':
                p.phase = PhaseError
                p.errorCode = Http400
                return false
              var num = 0
              var j = valStart
              while j < i and char(buf[j]) in '0'..'9':
                let digit = ord(char(buf[j])) - ord('0')
                if num > (high(int) - digit) div 10:
                  p.phase = PhaseError
                  p.errorCode = Http413
                  return false
                num = num * 10 + digit
                inc j
              if j == valStart:
                p.phase = PhaseError
                p.errorCode = Http400
                return false
              # The entire field-value after leading OWS must be digits
              # (trailing OWS allowed). A value like `5x`, `1e3` or `5.0`
              # is not a valid Content-Length and must be rejected — silently
              # truncating it (e.g. to 5/1) would make two servers disagree on
              # the message boundary.
              var k = j
              while k < i and (char(buf[k]) == ' ' or char(buf[k]) == '\t'):
                inc k
              if k < i:
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
                p.transferEncoded = true
                var valStart = lineStart + teKey.len
                while valStart < i and char(buf[valStart]) == ' ':
                  inc valStart
                # Only enable chunked framing when the FINAL comma-separated
                # token is exactly "chunked" (RFC 7230 §3.3.1). A TE value like
                # "gzip" or "identity" must NOT enable chunked body parsing.
                var j = i - 1
                while j >= valStart and (char(buf[j]) == ' ' or char(buf[j]) == '\t'):
                  dec j
                let tokEnd = j + 1
                while j >= valStart and char(buf[j]) != ',':
                  dec j
                var tokStart = j + 1
                while tokStart < tokEnd and
                      (char(buf[tokStart]) == ' ' or char(buf[tokStart]) == '\t'):
                  inc tokStart
                let tokLen = tokEnd - tokStart
                if tokLen == 7:
                  const chunkedTok = "chunked"
                  var isChunked = true
                  for k in 0 ..< 7:
                    let ch = char(buf[tokStart + k])
                    if ch != chunkedTok[k] and ch != (char(ord(chunkedTok[k]) xor 32)):
                      isChunked = false
                      break
                  if isChunked:
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

        # Quick check for Expect: 100-continue
        if not matched and lineLen >= 16:
          let c = char(buf[lineStart])
          if c == 'E' or c == 'e':
            var isExp = true
            const expKey = "expect:"
            if lineLen >= expKey.len:
              for j in 0 ..< expKey.len:
                let ch = char(buf[lineStart + j])
                if ch != expKey[j] and ch != (char(ord(expKey[j]) xor 32)):
                  isExp = false
                  break
              if isExp:
                var valStart = lineStart + expKey.len
                while valStart < i and char(buf[valStart]) == ' ':
                  inc valStart
                let valLen = i - valStart
                const expectKey = "100-continue"
                if valLen >= expectKey.len:
                  var isEC = true
                  for j in 0 ..< expectKey.len:
                    let ch = char(buf[valStart + j])
                    if ch != expectKey[j]:
                      isEC = false
                      break
                  if isEC:
                    p.expectContinue = true

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

  # Reject ambiguous framing: a message carrying BOTH Content-Length and
  # Transfer-Encoding is a request-smuggling vector (RFC 7230 §3.3.3 / RFC 9112
  # §6.3). The two interpretations cannot coincide, so a proxy front-end that
  # honours one and a back-end that honours the other would desync. Reject it.
  if p.transferEncoded and p.contentLength >= 0:
    p.phase = PhaseError
    p.errorCode = Http400
    return false

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
  ## The decoded-body cap is enforced even when maxBodySize == 0 (a hostile
  ## client must not drive unbounded RAM/disk through a chunked upload).
  let cap = if p.maxBodySize > 0: p.maxBodySize else: int64(MaxStreamBodySize)
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
          # Advance past the final CRLF so resetForNext/getRemainingData know
          # the exact end of the chunked message (previously the framing bytes
          # were left behind and the next keep-alive request was misparsed).
          p.bodyStart = pos + 2
          return true
        else:
          # Incomplete - need more data
          p.bodyStart = pos
          return false
      elif pos < p.bufLen and char(buf[pos]) == '\n':
        # Handle LF-only line ending
        p.phase = PhaseComplete
        p.bodyStart = pos + 1
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

      if int64(p.chunkBodyLen) + chunkSize > cap:
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
      if int64(p.chunkBodyLen) > cap:
        p.phase = PhaseError
        p.errorCode = Http413
        return false

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
        if int64(p.chunkBodyLen) > cap:
          p.phase = PhaseError
          p.errorCode = Http413
          return false

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

  # Streaming mode: after headers are parsed, body bytes go to callback.
  # Note: chunked bodies are NOT streamed here — they are buffered and decoded
  # (see the PhaseBody branch) so the callback receives decoded bytes and a
  # terminal `done=true` (raw chunk framing is never forwarded).
  if p.streamingBody and p.phase == PhaseBody:
    # Content-Length streaming: only forward body bytes, buffer leftover for next request
    let remaining = p.contentLength - p.bodyStreamed
    if remaining <= 0:
      p.bodyLen = p.contentLength
      p.phase = PhaseComplete
      return p.phase
    let bodyBytes = min(data.len, remaining)
    let streamCap = if p.maxBodySize > 0: p.maxBodySize
                    else: int64(MaxStreamBodySize)
    if p.bodyStreamed + int64(bodyBytes) > streamCap:
      # Upload exceeds the cap — reject before writing more to disk/RAM.
      p.phase = PhaseError
      p.errorCode = Http413
      return p.phase
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

  # Bound header-section buffering so an attacker cannot force a large
  # allocation with one oversized packet: while the header section is still
  # incomplete, only buffer up to HeaderBufCap, let the 414/431 checks run,
  # then buffer any body bytes that follow a completed header section.
  if p.phase == PhaseRequestLine or p.phase == PhaseHeaders:
    if p.bufLen + data.len > HeaderBufCap:
      let headRoom = HeaderBufCap - p.bufLen
      if headRoom > 0:
        p.ensureCapacity(headRoom)
        copyMem(addr p.buf[p.bufLen], unsafeAddr data[0], headRoom)
        p.bufLen += headRoom
      if p.phase == PhaseRequestLine:
        if not p.parseRequestLine(): return p.phase
      if p.phase == PhaseHeaders:
        if not p.scanHeaders(): return p.phase
      if p.phase == PhaseBody:
        # Headers completed inside the capped prefix — buffer the rest as body.
        let offset = headRoom
        if data.len - offset > 0:
          p.ensureCapacity(data.len - offset)
          copyMem(addr p.buf[p.bufLen], unsafeAddr data[offset], data.len - offset)
          p.bufLen += data.len - offset
        # Fall through so the PhaseBody completion check below runs.
      elif p.phase != PhaseError:
        # Headers still incomplete at the cap — reject without further growth.
        p.phase = PhaseError
        p.errorCode = Http431
        return p.phase
    else:
      p.ensureCapacity(data.len)
      if data.len > 0:
        copyMem(addr p.buf[p.bufLen], unsafeAddr data[0], data.len)
        p.bufLen += data.len
  else:
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
    if p.onBodyData != nil and not p.streamingBody and not p.transferChunked:
      # Activate streaming mode instead of buffering the body.
      # This must happen before the buffered body completion check
      # so that even a fully-arrived body is streamed via callback.
      # Chunked bodies are excluded: they are buffered and decoded so the
      # callback receives decoded bytes with a terminal done=true.
      p.streamingBody = true
      let bodyStart = p.headerEnd
      let bodyInBuf = p.bufLen - bodyStart
      if bodyInBuf > 0:
        let bytesToStream = if p.contentLength > 0:
                              min(bodyInBuf, p.contentLength)
                            else:
                              bodyInBuf
        if bytesToStream > 0:
          let doneAfter = p.contentLength > 0 and p.bodyStreamed + bytesToStream >= p.contentLength
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
      if p.contentLength > 0:
        if p.bodyStreamed >= p.contentLength:
          p.bodyLen = p.contentLength
          p.phase = PhaseComplete
      return p.phase

    if p.transferChunked:
      # Chunked transfer encoding: decode into the buffer, then deliver the
      # decoded body to onBodyData (if set) when the terminating chunk arrives.
      if p.bodyStart == 0:
        p.bodyStart = p.headerEnd
      if p.parseChunkedBody():
        p.phase = PhaseComplete
        if p.onBodyData != nil and p.chunkBodyLen > 0:
          p.onBodyData(p.buf.toOpenArray(p.headerEnd, p.headerEnd + p.chunkBodyLen - 1), true)
        p.bodyStreamed = p.chunkBodyLen.int64
    else:
      # Content-Length based
      let expected = p.contentEnd
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
    if p.onBodyData != nil and not p.streamingBody and not p.transferChunked:
      p.streamingBody = true
      let bodyStart = p.headerEnd
      let bodyInBuf = p.bufLen - bodyStart
      if bodyInBuf > 0:
        let bytesToStream = if p.contentLength > 0:
                              min(bodyInBuf, p.contentLength)
                            else:
                              bodyInBuf
        if bytesToStream > 0 and p.onBodyData != nil:
          let doneAfter = p.contentLength > 0 and p.bodyStreamed + bytesToStream >= p.contentLength
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
      if p.contentLength > 0:
        if p.bodyStreamed >= p.contentLength:
          p.bodyLen = p.contentLength
          p.phase = PhaseComplete
      return
    if p.transferChunked:
      if p.bodyStart == 0:
        p.bodyStart = p.headerEnd
      if p.parseChunkedBody():
        p.phase = PhaseComplete
        if p.onBodyData != nil and p.chunkBodyLen > 0:
          p.onBodyData(p.buf.toOpenArray(p.headerEnd, p.headerEnd + p.chunkBodyLen - 1), true)
        p.bodyStreamed = p.chunkBodyLen.int64
    elif p.contentLength > 0:
      let expected = p.contentEnd
      if p.bufLen >= expected:
        p.bodyLen = p.contentLength
        p.phase = PhaseComplete

func isComplete*(p: HttpParser): bool {.inline.} =
  p.phase == PhaseComplete

func isError*(p: HttpParser): bool {.inline.} =
  p.phase == PhaseError

proc setError*(p: HttpParser, code: HttpCode) {.inline.} =
  ## Put the parser into the error state with the given HTTP status code.
  p.phase = PhaseError
  p.errorCode = code

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
    elif p.contentLength > 0 and p.bufLen >= p.contentEnd:
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
  elif p.contentLength > 0 and p.bufLen >= p.contentEnd:
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
  try:
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
  except MultipartSizeLimitError:
    # Body exceeded a configured size limit — return nil so the handler can
    # decide (the server's auto-stream path replies 413 itself).
    return nil
  except MultipartInvalidHeader:
    # Malformed part headers — never let a CatchableError escape into the
    # handler's call stack as an unhandled exception.
    return nil

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
  # Private (0600), O_EXCL temp file: world-readable uploads and the temp-file
  # symlink race are both prevented. Retry on the astronomically unlikely
  # chance the generated name already exists (e.g. attacker pre-created it).
  var filePath = ""
  var f: File
  for attempt in 0 ..< 8:
    filePath = dir / $genOid()
    try:
      f = openPrivateFile(filePath)
      break
    except IOError:
      filePath = ""
  if filePath.len == 0:
    return ""
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
  let consumed = if p.transferChunked: p.bodyStart  # past the final CRLF
                 elif p.contentLength > 0: p.contentEnd
                 else: p.headerEnd
  let leftover = p.bufLen - consumed
  if leftover > 0:
    result = newSeq[byte](leftover)
    copyMem(addr result[0], unsafeAddr p.buf[consumed], leftover)
  else:
    result = @[]
