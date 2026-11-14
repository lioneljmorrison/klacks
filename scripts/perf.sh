#!/usr/bin/env bash
# Performance gate (S-53): start a dev klacks server against the running
# stack, drive the G-8 load profile through it with cmd/klacksload, and
# exit non-zero if the run misses its thresholds. `make perf` builds the
# binaries and runs this; run it directly to use prebuilt ones.
#
# Needs the stack up (`make up`) and KLACKS_POSTGRES_DSN / KLACKS_SCYLLA_HOSTS
# (the Makefile exports them from .env). Every knob below can be overridden
# from the environment, e.g. PERF_ROOMS=100 PERF_RATE=100 for a scaled run.
#
# Kept to bash 3.2 and BSD tools so it runs on macOS as well as Linux.
set -euo pipefail

KLACKS=${KLACKS:-bin/klacks}
KLACKSLOAD=${KLACKSLOAD:-bin/klacksload}

# G-8 (plan Phase 5): 10k connections, 1k msg/s, p99 delivery < 200 ms.
PERF_ROOMS=${PERF_ROOMS:-1000}
PERF_MEMBERS=${PERF_MEMBERS:-10}
PERF_RATE=${PERF_RATE:-1000}
PERF_DURATION=${PERF_DURATION:-60s}
PERF_WARMUP=${PERF_WARMUP:-10s}
PERF_MAX_P99=${PERF_MAX_P99:-200ms}
# Postgres pool for the server: the pgx default (max(4, CPUs)) queues
# publishes at 1k msg/s; see docs/operations.md for sizing.
PERF_POOL=${PERF_POOL:-60}
PERF_HTTP_PORT=${PERF_HTTP_PORT:-18080}
PERF_METRICS_PORT=${PERF_METRICS_PORT:-19090}
PERF_OUT=${PERF_OUT:-bin/perf}

: "${KLACKS_POSTGRES_DSN:?set KLACKS_POSTGRES_DSN (make env creates .env)}"
: "${KLACKS_SCYLLA_HOSTS:?set KLACKS_SCYLLA_HOSTS (make env creates .env)}"

case $KLACKS_POSTGRES_DSN in
*\?*) dsn="$KLACKS_POSTGRES_DSN&pool_max_conns=$PERF_POOL" ;;
*) dsn="$KLACKS_POSTGRES_DSN?pool_max_conns=$PERF_POOL" ;;
esac

mkdir -p "$PERF_OUT"
log="$PERF_OUT/server.log"
report="$PERF_OUT/report.txt"
base="http://127.0.0.1:$PERF_HTTP_PORT"
metrics="http://127.0.0.1:$PERF_METRICS_PORT"

if curl -s -o /dev/null "$base/healthz"; then
	echo "perf: something already listens on $base; set PERF_HTTP_PORT" >&2
	exit 2
fi

"$KLACKS" migrate up

server=
cleanup() {
	if [ -n "$server" ] && kill -0 "$server" 2>/dev/null; then
		kill "$server" 2>/dev/null || true
		wait "$server" 2>/dev/null || true
	fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

KLACKS_ENV=dev \
	KLACKS_LOG_LEVEL=warn \
	KLACKS_HTTP_ADDR="127.0.0.1:$PERF_HTTP_PORT" \
	KLACKS_METRICS_ADDR="127.0.0.1:$PERF_METRICS_PORT" \
	KLACKS_POSTGRES_DSN="$dsn" \
	"$KLACKS" serve >"$log" 2>&1 &
server=$!

tries=0
until curl -fs -o /dev/null "$base/readyz"; do
	tries=$((tries + 1))
	if ! kill -0 "$server" 2>/dev/null || [ "$tries" -ge 60 ]; then
		echo "perf: server did not become ready; last lines of $log:" >&2
		tail -n 20 "$log" >&2
		exit 1
	fi
	sleep 0.5
done

{
	echo "perf: $(uname -srm), $(date -u +%Y-%m-%dT%H:%M:%SZ), commit $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
	echo "perf: rooms=$PERF_ROOMS members=$PERF_MEMBERS rate=$PERF_RATE duration=$PERF_DURATION warmup=$PERF_WARMUP pool=$PERF_POOL max-p99=$PERF_MAX_P99"
} | tee "$report"

status=0
"$KLACKSLOAD" -base "$base" -metrics "$metrics" \
	-rooms "$PERF_ROOMS" -members "$PERF_MEMBERS" -rate "$PERF_RATE" \
	-duration "$PERF_DURATION" -warmup "$PERF_WARMUP" -max-p99 "$PERF_MAX_P99" \
	2>&1 | tee -a "$report" || status=$?

if [ "$status" -ne 0 ]; then
	echo "perf: FAILED (report: $report, server log: $log)" >&2
fi
exit "$status"
