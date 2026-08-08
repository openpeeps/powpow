## audit/01_multipart_parser_crash.nim
##
## P0 — Remote crash (IndexDefect) in the multipart parser on malformed part
## headers. Reachable from powpow via getMultipart() and the auto-streaming
## upload path. A Defect (IndexDefect) is unrecoverable and aborts the event
## loop / process; a CatchableError must be raised instead.
##
## Pre-fix: DEFECT (index out of bounds / index N not in 0..M).
## Post-fix: the parser raises a CatchableError (or skips the part) — no crash.

import multipart
import std/[unittest, strutils, os]

proc classify(body: string): string =
  let ct = "multipart/form-data; boundary=X"
  var ms = newMultipartStreamer(ct)
  try:
    ms.feed(body)
    result = "ok parts=" & $ms.len
  except MultipartSizeLimitError:
    result = "size-limit-error"
  except MultipartInvalidHeader:
    result = "invalid-header"
  except MultipartConfigError:
    result = "config-error"
  except Defect as e:
    result = "DEFECT: " & e.msg
  except CatchableError as e:
    result = "CATCHABLE: " & e.msg
  try: ms.cleanup()
  except: discard

suite "multipart parser never crashes on malformed part headers":

  test "CD parameter with no '=' (Content-Disposition: form-data; name)":
    let r = classify("--X\r\nContent-Disposition: form-data; name\r\n\r\nvalue\r\n--X--\r\n")
    check not r.startsWith("DEFECT")
    check r != "DEFECT: index 1 not in 0 .. 0"

  test "CD with no parameters at all":
    let r = classify("--X\r\nContent-Disposition: form-data\r\n\r\nvalue\r\n--X--\r\n")
    check not r.startsWith("DEFECT")

  test "file part with name but no filename":
    let r = classify("--X\r\nContent-Disposition: form-data; name=\"f\"\r\nContent-Type: text/plain\r\n\r\ndata\r\n--X--\r\n")
    check not r.startsWith("DEFECT")

  test "file part with filename but no name":
    let r = classify("--X\r\nContent-Disposition: form-data; filename=\"f.txt\"\r\nContent-Type: text/plain\r\n\r\ndata\r\n--X--\r\n")
    check not r.startsWith("DEFECT")

  test "CD only + Content-Type (no name/filename)":
    let r = classify("--X\r\nContent-Disposition: form-data\r\nContent-Type: text/plain\r\n\r\ndata\r\n--X--\r\n")
    check not r.startsWith("DEFECT")

  test "well-formed parts still parse (no false positives)":
    let body = "--X\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--X--\r\n"
    var ms = newMultipartStreamer("multipart/form-data; boundary=X")
    ms.feed(body)
    check ms.len == 1
    check ms.boundaries()[0].dataType == MultipartText
    check ms.boundaries()[0].fieldName == "a"
    check ms.boundaries()[0].value == "v"
    ms.cleanup()
