## audit/05_tempfile_permissions.nim
##
## P2 — Uploaded temp files must not be world-readable (pre-fix 0644 leaks
## upload contents to other local users) and should not follow pre-created
## symlinks (pre-fix `open(fmWrite)` follows a symlink placed at the guessed
## OID path, letting a local attacker clobber an arbitrary file).

import multipart
import std/[unittest, os]

suite "multipart temp files are private and symlink-safe":

  test "uploaded file is not world/group readable":
    let tmp = getTempDir() / "pp_audit_perms_" & $getCurrentProcessId()
    createDir(tmp)
    defer: removeDir(tmp)
    var ms = newMultipartStreamer("multipart/form-data; boundary=X", tmpDir = tmp)
    ms.feed("--X\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nSECRET\r\n--X--\r\n")
    for b in ms.boundaries():
      if b.dataType == MultipartFile:
        let mode = getFilePermissions(b.filePath)
        check fpOthersRead notin mode
        check fpGroupRead notin mode
    ms.cleanup()

  test "openPrivateFile refuses to follow a pre-existing symlink":
    # The multipart temp-file open uses O_EXCL: a symlink planted at the target
    # path must cause an IOError, not a write through the symlink.
    let tmp = getTempDir() / "pp_audit_sym_" & $getCurrentProcessId()
    createDir(tmp)
    defer: removeDir(tmp)
    let target = getTempDir() / "pp_audit_victim_" & $getCurrentProcessId()
    writeFile(target, "DO-NOT-OVERWRITE")
    defer: removeFile(target)
    createSymlink(target, tmp / "sneaky.txt")
    var refused = false
    try:
      let f = openPrivateFile(tmp / "sneaky.txt")
      f.close()
    except IOError:
      refused = true
    check refused
    check readFile(target) == "DO-NOT-OVERWRITE"
