#!/bin/sh
# Conformance scenario tests under the `conformance` build tag. Owned
# by the `conformance` CI job. The default `test` job does NOT run
# these — the scenario stitches together every wire shape end-to-end
# and is comprehensive enough that running it on every PR would add
# noticeable time without commensurate signal for the bulk of changes
# (which never touch the wire layer).
#
# -race + -shuffle + -count=1 mirror the standard test job's flags,
# for the same reasons documented in check-test.sh: catch races,
# surface inter-test ordering deps, defeat the test cache.
#
# The build tag is the load-bearing piece — `go test ./conformance/...`
# without `-tags conformance` runs only the default-build
# fixtures_test.go, which is the byte-stability check. The scenario
# tests sit behind the tag so they're explicit to invoke.
set -eu

echo "==> go test -tags conformance -race -shuffle=on -count=1 ./conformance/..."
go test -tags conformance -race -shuffle=on -count=1 ./conformance/...
echo "OK: conformance scenarios passed."
