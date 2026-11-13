#!/usr/bin/env bash
# Create an empty up/down migration pair with the next version number.
# Usage: scripts/new-migration.sh postgres|scylla short_name
set -euo pipefail

store="${1:-}"
name="${2:-}"
case "$store" in
  postgres) ext=sql ;;
  scylla)   ext=cql ;;
  *) echo "usage: $0 postgres|scylla short_name" >&2; exit 2 ;;
esac
if [[ ! "$name" =~ ^[a-z0-9_]+$ ]]; then
  echo "name must match [a-z0-9_]+ (got '$name')" >&2
  exit 2
fi

dir="$(dirname "$0")/../migrations/$store"
last=0
for f in "$dir"/[0-9]*_*."up.$ext"; do
  [[ -e "$f" ]] || continue
  v=$(basename "$f" | cut -d_ -f1)
  (( 10#$v > last )) && last=$((10#$v))
done
next=$(printf '%06d' $((last + 1)))

for d in up down; do
  f="$dir/${next}_${name}.${d}.${ext}"
  : > "$f"
  echo "created migrations/$store/$(basename "$f")"
done
