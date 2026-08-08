# audit — Security regression harness for powpow (+ the multipart dependency).
#
# Each file is a standalone runnable test. They are deliberately RED on the
# pre-fix code and GREEN after the corresponding fix, so they can be run
# periodically to catch regressions.
#
# Run all audits:
#   cd <powpow repo>
#   for f in audit/[0-9]*.nim; do nim c -r --hints:off --verbosity:0 "$f"; done
#
# The config below puts the local powpow src on the path, and (for the
# multipart-specific audits) the sibling multipart checkout ahead of the
# nimble-installed copy so audits exercise the source we actually patch.

switch("path", "$projectDir/../src")
switch("path", "$projectDir/../../multipart/src")
