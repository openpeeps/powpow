## tests/test_multipart_streamer.nim — Tests for the streaming multipart parser.
##
## Tests: single feed (equivalence with buffered parser), incremental feeds
## (split across boundaries), text fields, file uploads, partial boundary
## matches spanning feeds, mixed parts, edge cases.

import ../src/powpow/proto/multipart
import std/[os, unittest, strutils]

const
  boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
  contentType = "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"

# ── Helper: build multipart body ──────────────────────────────────────────────

proc makeTextBody(fields: openArray[(string, string)]): string =
  ## Build a multipart body with text fields only.
  var parts: seq[string]
  for (name, value) in fields:
    parts.add("--" & boundary & "\r\n" &
              "Content-Disposition: form-data; name=\"" & name & "\"\r\n\r\n" &
              value & "\r\n")
  parts.add("--" & boundary & "--\r\n")
  result = parts.join("")

proc makeFileBody(fieldName, fileName, fileType, fileContent: string): string =
  ## Build a multipart body with one file field.
  result = "--" & boundary & "\r\n" &
           "Content-Disposition: form-data; name=\"" & fieldName & "\"; filename=\"" & fileName & "\"\r\n" &
           "Content-Type: " & fileType & "\r\n\r\n" &
           fileContent & "\r\n" &
           "--" & boundary & "--\r\n"

proc makeMixedBody(textField: (string, string), fileField: (string, string, string, string)): string =
  ## Build a multipart body with one text field and one file field.
  let (tName, tValue) = textField
  let (fName, fFileName, fFileType, fContent) = fileField
  result = "--" & boundary & "\r\n" &
           "Content-Disposition: form-data; name=\"" & tName & "\"\r\n\r\n" &
           tValue & "\r\n" &
           "--" & boundary & "\r\n" &
           "Content-Disposition: form-data; name=\"" & fName & "\"; filename=\"" & fFileName & "\"\r\n" &
           "Content-Type: " & fFileType & "\r\n\r\n" &
           fContent & "\r\n" &
           "--" & boundary & "--\r\n"

# ── Test 1: Single text field, single feed ─────────────────────────────────────

test "streamer_single_text_single_feed":
  let body = makeTextBody([("username", "Alice")])
  var ms = newMultipartStreamer(contentType)
  ms.feed(body)
  doAssert ms.isComplete()
  doAssert ms.len == 1
  doAssert ms.boundaries()[0].dataType == MultipartText
  doAssert ms.boundaries()[0].fieldName == "username"
  doAssert ms.boundaries()[0].value == "Alice"
  ms.cleanup()

# ── Test 2: Single text field, incremental feeds ──────────────────────────────

test "streamer_single_text_incremental":
  let body = makeTextBody([("username", "Alice")])
  var ms = newMultipartStreamer(contentType)
  # Split at various points to test boundary spanning across feeds
  let chunkSize = max(1, body.len div 5)
  var pos = 0
  while pos < body.len:
    let endPos = min(pos + chunkSize, body.len)
    ms.feed(body[pos ..< endPos])
    pos = endPos
  doAssert ms.isComplete()
  doAssert ms.len == 1
  doAssert ms.boundaries()[0].fieldName == "username"
  doAssert ms.boundaries()[0].value == "Alice"
  ms.cleanup()

# ── Test 3: Multiple text fields ──────────────────────────────────────────────

test "streamer_multiple_text_fields":
  let body = makeTextBody([("name", "Bob"), ("email", "bob@example.com"), ("city", "NYC")])
  var ms = newMultipartStreamer(contentType)
  ms.feed(body)
  doAssert ms.isComplete()
  doAssert ms.len == 3
  doAssert ms.boundaries()[0].fieldName == "name"
  doAssert ms.boundaries()[0].value == "Bob"
  doAssert ms.boundaries()[1].fieldName == "email"
  doAssert ms.boundaries()[1].value == "bob@example.com"
  doAssert ms.boundaries()[2].fieldName == "city"
  doAssert ms.boundaries()[2].value == "NYC"
  ms.cleanup()

# ── Test 4: File upload, single feed ──────────────────────────────────────────

test "streamer_file_single_feed":
  let body = makeFileBody("upload", "test.txt", "text/plain", "Hello, file upload!")
  var ms = newMultipartStreamer(contentType)
  ms.feed(body)
  doAssert ms.isComplete()
  doAssert ms.len == 1
  let b = ms.boundaries()[0]
  doAssert b.dataType == MultipartFile
  doAssert b.fieldName == "upload"
  doAssert b.fileName == "test.txt"
  doAssert b.fileType == "text/plain"
  doAssert b.fileSize == 19  # "Hello, file upload!"
  # Verify file content was written to disk
  doAssert fileExists(b.filePath)
  let content = readFile(b.filePath)
  doAssert content == "Hello, file upload!"
  ms.cleanup()

# ── Test 5: File upload, incremental feeds ─────────────────────────────────────

test "streamer_file_incremental":
  let body = makeFileBody("upload", "test2.txt", "text/plain", "Hello, incremental file!")
  var ms = newMultipartStreamer(contentType)
  # Feed in 5-byte chunks
  var pos = 0
  while pos < body.len:
    let endPos = min(pos + 5, body.len)
    ms.feed(body[pos ..< endPos])
    pos = endPos
  doAssert ms.isComplete()
  doAssert ms.len == 1
  let b = ms.boundaries()[0]
  doAssert b.fileSize == 24  # "Hello, incremental file!"
  doAssert fileExists(b.filePath)
  let content = readFile(b.filePath)
  doAssert content == "Hello, incremental file!"
  ms.cleanup()

# ── Test 6: Mixed text and file ────────────────────────────────────────────────

test "streamer_mixed_text_and_file":
  let body = makeMixedBody(
    ("description", "My document"),
    ("file", "doc.txt", "text/plain", "Document content here")
  )
  var ms = newMultipartStreamer(contentType)
  ms.feed(body)
  doAssert ms.isComplete()
  doAssert ms.len == 2

  doAssert ms.boundaries()[0].dataType == MultipartText
  doAssert ms.boundaries()[0].fieldName == "description"
  doAssert ms.boundaries()[0].value == "My document"

  doAssert ms.boundaries()[1].dataType == MultipartFile
  doAssert ms.boundaries()[1].fieldName == "file"
  doAssert ms.boundaries()[1].fileName == "doc.txt"
  doAssert fileExists(ms.boundaries()[1].filePath)
  doAssert readFile(ms.boundaries()[1].filePath) == "Document content here"
  ms.cleanup()

# ── Test 7: Boundary split across feeds ─────────────────────────────────────────

test "streamer_boundary_split_across_feeds":
  # Construct body where \r\n--boundary is split across feed boundaries
  let body = makeTextBody([("name", "SplitTest")])
  var ms = newMultipartStreamer(contentType)

  # Find the first \r\n--boundary in the body (the one between the value and the end marker)
  let endMarker = "\r\n--" & boundary & "--"
  let endMarkerPos = body.find(endMarker)
  doAssert endMarkerPos > 0

  # Feed up to just before the \r\n at the end marker
  # This ensures \r\n--boundary-- is split across two feeds
  let splitPos = endMarkerPos + 1  # split after \r
  ms.feed(body[0 ..< splitPos])
  doAssert not ms.isComplete()
  ms.feed(body[splitPos ..< body.len])
  doAssert ms.isComplete()

  doAssert ms.len == 1
  doAssert ms.boundaries()[0].fieldName == "name"
  doAssert ms.boundaries()[0].value == "SplitTest"
  ms.cleanup()

# ── Test 8: Feed byte-by-byte ──────────────────────────────────────────────────

test "streamer_byte_by_byte":
  let body = makeTextBody([("key", "value")])
  var ms = newMultipartStreamer(contentType)
  for c in body:
    ms.feed($c)
  doAssert ms.isComplete()
  doAssert ms.len == 1
  doAssert ms.boundaries()[0].fieldName == "key"
  doAssert ms.boundaries()[0].value == "value"
  ms.cleanup()

# ── Test 9: Empty text field ───────────────────────────────────────────────────

test "streamer_empty_text_field":
  let body = makeTextBody([("empty", "")])
  var ms = newMultipartStreamer(contentType)
  ms.feed(body)
  doAssert ms.isComplete()
  doAssert ms.len == 1
  doAssert ms.boundaries()[0].fieldName == "empty"
  doAssert ms.boundaries()[0].value == ""
  ms.cleanup()

# ── Test 10: Binary file content (with \r\n in file data) ────────────────────────

test "streamer_file_with_crlf_in_data":
  let fileContent = "line1\r\nline2\r\nline3"
  let body = makeFileBody("file", "test.bin", "application/octet-stream", fileContent)
  var ms = newMultipartStreamer(contentType)
  ms.feed(body)
  doAssert ms.isComplete()
  doAssert ms.len == 1
  let b = ms.boundaries()[0]
  doAssert fileExists(b.filePath)
  doAssert readFile(b.filePath) == fileContent
  ms.cleanup()

# ── Test 11: File with \r\n that could be mistaken for boundary ─────────────────

test "streamer_file_with_boundary_like_data":
  # File data contains \r\n-- (but not the full boundary)
  let fileContent = "data\r\n--almost-boundary\r\nmore-data"
  let body = makeFileBody("file", "tricky.bin", "application/octet-stream", fileContent)
  var ms = newMultipartStreamer(contentType)
  ms.feed(body)
  doAssert ms.isComplete()
  doAssert ms.len == 1
  let b = ms.boundaries()[0]
  doAssert fileExists(b.filePath)
  doAssert readFile(b.filePath) == fileContent
  ms.cleanup()

# ── Test 12: Large file (1KB) incremented across feeds ──────────────────────────

test "streamer_large_file_incremental":
  let fileContent = "A".repeat(1024)
  let body = makeFileBody("bigfile", "big.dat", "application/octet-stream", fileContent)
  var ms = newMultipartStreamer(contentType)
  var pos = 0
  while pos < body.len:
    let endPos = min(pos + 64, body.len)
    ms.feed(body[pos ..< endPos])
    pos = endPos
  doAssert ms.isComplete()
  doAssert ms.len == 1
  let b = ms.boundaries()[0]
  doAssert b.fileSize == 1024
  doAssert fileExists(b.filePath)
  doAssert readFile(b.filePath).len == 1024
  ms.cleanup()

# ── Test 13: feed with ptr UncheckedArray[byte] ─────────────────────────────────

test "streamer_feed_ptr_uncheckedarray":
  let body = makeTextBody([("test", "ptr")])
  var ms = newMultipartStreamer(contentType)
  var data = newSeq[byte](body.len)
  copyMem(addr data[0], body.cstring, body.len)
  let ptrData = cast[ptr UncheckedArray[byte]](addr data[0])
  ms.feed(ptrData, body.len)
  doAssert ms.isComplete()
  doAssert ms.len == 1
  doAssert ms.boundaries()[0].fieldName == "test"
  doAssert ms.boundaries()[0].value == "ptr"
  ms.cleanup()

# ── Test 14: Progressive feed (check isComplete before done) ────────────────────

test "streamer_progressive_isComplete":
  let body = makeTextBody([("key", "val")])
  var ms = newMultipartStreamer(contentType)
  # Feed just the preamble + boundary (not enough to complete)
  ms.feed(body[0 ..< 10])
  doAssert not ms.isComplete()
  # Feed the rest
  ms.feed(body[10 ..< body.len])
  doAssert ms.isComplete()
  ms.cleanup()

# ── Test 15: Data with \r\n inside text field ──────────────────────────────────

test "streamer_text_field_with_newlines":
  let body = makeTextBody([("message", "Hello\r\nWorld")])
  var ms = newMultipartStreamer(contentType)
  ms.feed(body)
  doAssert ms.isComplete()
  doAssert ms.boundaries()[0].value == "Hello\r\nWorld"
  ms.cleanup()

# ── Test 16: Preamble before first boundary ──────────────────────────────────────

test "streamer_with_preamble":
  # Some multipart bodies have preamble data before the first boundary
  let preamble = "This is preamble data that should be ignored.\r\n"
  let bodyContent = "--" & boundary & "\r\n" &
                    "Content-Disposition: form-data; name=\"field1\"\r\n\r\n" &
                    "value1\r\n" &
                    "--" & boundary & "--\r\n"
  let body = preamble & bodyContent
  var ms = newMultipartStreamer(contentType)
  ms.feed(body)
  doAssert ms.isComplete()
  doAssert ms.len == 1
  doAssert ms.boundaries()[0].fieldName == "field1"
  doAssert ms.boundaries()[0].value == "value1"
  ms.cleanup()

# ── Test 17: Multiple feeds where boundary split is in the middle ────────────────

test "streamer_boundary_split_middle":
  let body = makeTextBody([("x", "y")])
  # Find the closing boundary marker (second occurrence of --boundary)
  let firstPos = body.find("--" & boundary)
  doAssert firstPos >= 0
  let secondPos = body.find("--" & boundary, firstPos + boundary.len + 2)
  doAssert secondPos > firstPos
  # Split exactly at the "--" of the closing boundary
  let splitPos = secondPos
  var ms = newMultipartStreamer(contentType)
  ms.feed(body[0 ..< splitPos])
  doAssert not ms.isComplete()
  ms.feed(body[splitPos ..< body.len])
  doAssert ms.isComplete()
  doAssert ms.boundaries()[0].fieldName == "x"
  doAssert ms.boundaries()[0].value == "y"
  ms.cleanup()

# ── Test 18: Two files ──────────────────────────────────────────────────────────

test "streamer_two_files":
  let file1Content = "File One Content"
  let file2Content = "File Two Content"
  let body = "--" & boundary & "\r\n" &
             "Content-Disposition: form-data; name=\"file1\"; filename=\"a.txt\"\r\n" &
             "Content-Type: text/plain\r\n\r\n" &
             file1Content & "\r\n" &
             "--" & boundary & "\r\n" &
             "Content-Disposition: form-data; name=\"file2\"; filename=\"b.txt\"\r\n" &
             "Content-Type: text/plain\r\n\r\n" &
             file2Content & "\r\n" &
             "--" & boundary & "--\r\n"
  var ms = newMultipartStreamer(contentType)
  ms.feed(body)
  doAssert ms.isComplete()
  doAssert ms.len == 2

  doAssert ms.boundaries()[0].fieldName == "file1"
  doAssert ms.boundaries()[0].fileName == "a.txt"
  doAssert fileExists(ms.boundaries()[0].filePath)
  doAssert readFile(ms.boundaries()[0].filePath) == file1Content

  doAssert ms.boundaries()[1].fieldName == "file2"
  doAssert ms.boundaries()[1].fileName == "b.txt"
  doAssert fileExists(ms.boundaries()[1].filePath)
  doAssert readFile(ms.boundaries()[1].filePath) == file2Content
  ms.cleanup()

# ── Test 19: Equivalence with buffered parser ───────────────────────────────────

test "streamer_equivalence_with_buffered_parser":
  let body = makeMixedBody(
    ("title", "Test Document"),
    ("attachment", "doc.pdf", "application/pdf", "PDF content here")
  )
  # Buffered parser
  var mp = initMultipart(contentType)
  mp.parse(body)
  # Streaming parser
  var ms = newMultipartStreamer(contentType)
  ms.feed(body)
  doAssert ms.isComplete()

  doAssert ms.len == mp.len
  var msItems: seq[Boundary]
  var mpItems: seq[Boundary]
  for b in ms: msItems.add(b)
  for b in mp: mpItems.add(b)
  for i in 0 ..< msItems.len:
    doAssert msItems[i].fieldName == mpItems[i].fieldName
    doAssert msItems[i].dataType == mpItems[i].dataType
    case msItems[i].dataType
    of MultipartText:
      doAssert msItems[i].value == mpItems[i].value
    of MultipartFile:
      doAssert msItems[i].fileName == mpItems[i].fileName
      doAssert msItems[i].fileType == mpItems[i].fileType
      doAssert readFile(msItems[i].filePath) == readFile(mpItems[i].filePath)

  ms.cleanup()
  mp.cleanup()