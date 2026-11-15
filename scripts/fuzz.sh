#!/usr/bin/env bash
# Run every Go fuzz target in the module for FUZZTIME each (S-35).
# `go test -fuzz` takes one target per run, so this lists them per package.
# A failure leaves its input in the package's testdata/fuzz/<Target>/; commit
# it with the fix so it stays in the seed corpus that plain `go test` runs.
set -euo pipefail
fuzztime="${FUZZTIME:-10s}"
failed=0
for pkg in $(go list ./...); do
  for target in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
    echo "== $pkg $target ($fuzztime)"
    if ! go test -run '^$' -fuzz "^${target}\$" -fuzztime "$fuzztime" "$pkg"; then
      failed=1
    fi
  done
done
exit "$failed"
