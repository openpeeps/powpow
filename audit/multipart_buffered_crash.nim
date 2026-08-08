## audit/02_multipart_buffered_crash.nim
##
## P2 — Buffered parser crashes with IndexDefect when the body has no leading
## boundary (preamble or garbage): `mp.boundaries[^1]` on an empty sequence.
##
## Pre-fix: DEFECT "index out of bounds, the container is empty".
## Post-fix: preamble/epilogue bytes are handled without crashing.

import multipart
import std/[unittest, strutils]

proc classify(body: string): string =
  let ct = "multipart/form-data; boundary=X"
  var mp = initMultipart(ct)
  try:
    mp.parse(body)
    result = "ok parts=" & $mp.len
  except Defect as e:
    result = "DEFECT: " & e.msg
  except CatchableError as e:
    result = "CATCHABLE: " & e.msg
  try: mp.cleanup()
  except: discard

suite "buffered multipart parser survives bodies without a leading boundary":

  test "preamble before first boundary":
    let r = classify("PREAMBLE\r\n--X\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--X--\r\n")
    check not r.startsWith("DEFECT")

  test "garbage body with no boundary at all":
    let r = classify("garbage-no-boundary-at-all")
    check not r.startsWith("DEFECT")

  test "valid body still parses correctly":
    let body = "--X\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n--X--\r\n"
    var mp = initMultipart("multipart/form-data; boundary=X")
    mp.parse(body)
    check mp.len == 1
    for b in mp:
      check b.dataType == MultipartText
      check b.fieldName == "a"
      check b.value == "v"
    mp.cleanup()
