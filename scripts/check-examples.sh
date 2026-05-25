#!/bin/sh
# Build the runnable examples under examples/ to keep them honest as the
# library API surface evolves. Owned by the `examples` CI job. Each example
# is a separate Go module (its `go.mod` lives in the example directory) with
# a `replace` directive pointing at the library at `../..`, so `go build`
# from inside the example uses the in-tree library copy.
#
# Each example is added to `examples_dirs` below. Keep the list explicit
# rather than walking the tree — that way a half-finished new example does
# not accidentally land in CI before its README and behavior are settled.
#
# This is a pure build check: it does not run the examples (some of them
# stand up real servers and exit on their own clock), and it does not run
# their tests (examples are demonstrations, not test packages).
set -eu

examples_dirs="examples/as-rs-demo"

fail=0
for d in $examples_dirs; do
  echo "==> go build ./... in $d"
  ( cd "$d" && go build ./... ) || fail=1
done

[ "$fail" -eq 0 ] && echo "OK: examples build clean."
exit "$fail"
