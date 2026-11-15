#!/usr/bin/env bash
# Performance sweep (S-54): run scripts/perf.sh once per input line and
# append each run to a JSONL dataset, pass or fail. Each line is a set of
# KEY=VALUE assignments for that run, e.g.
#
#	PERF_RATE=500 PERF_POOL=60 VARIANT=base SYNC=on
#
# PERF_* go to perf.sh. VARIANT picks the server binary bin/klacks-$VARIANT
# (default: base -> bin/klacks). SYNC=on|off sets PostgreSQL
# synchronous_commit on PG_CONTAINER before the run (ALTER SYSTEM + reload).
# Every assignment is also recorded as a label, with machine, seq (run
# order), load1 (1-min load average before the run) and commit.
#
#	MACHINE=m4 OUT=perf-data/m4.jsonl scripts/perf-sweep.sh < plan.txt
#
# Stops when free disk drops below MIN_FREE_GB. Bash 3.2 / BSD safe.
set -uo pipefail

: "${MACHINE:?set MACHINE}"
: "${OUT:?set OUT (JSONL file)}"
MIN_FREE_GB=${MIN_FREE_GB:-2}
PG_CONTAINER=${PG_CONTAINER:-klacks-perf-postgres-1}
COMMIT=${PERF_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}

load1() {
	if [ -r /proc/loadavg ]; then cut -d' ' -f1 /proc/loadavg; else sysctl -n vm.loadavg | awk '{print $2}'; fi
}
free_gb() { df -Pk . | awk 'NR==2 {print int($4/1048576)}'; }

mkdir -p "$(dirname "$OUT")"
seq=0
while read -r line || [ -n "$line" ]; do
	case $line in '' | \#*) continue ;; esac
	seq=$((seq + 1))
	if [ "$(free_gb)" -lt "$MIN_FREE_GB" ]; then
		echo "sweep: under ${MIN_FREE_GB} GB free; stopping before run $seq" >&2
		exit 1
	fi
	(
		VARIANT=base SYNC=on
		labels=""
		for kv in $line; do
			export "${kv?}"
			labels="$labels -label $kv"
		done
		bin=bin/klacks
		[ "$VARIANT" = base ] || bin=bin/klacks-$VARIANT
		docker exec "$PG_CONTAINER" psql -qX -U klacks -d klacks \
			-c "ALTER SYSTEM SET synchronous_commit = $SYNC" -c "SELECT pg_reload_conf()" >/dev/null || exit 1
		l=$(load1)
		echo "sweep: run $seq [$line] load1=$l $(date -u +%H:%M:%S)"
		# shellcheck disable=SC2086 # labels is a word list on purpose
		KLACKS=$bin PERF_COMMIT=$COMMIT PERF_OUT=bin/perf-sweep scripts/perf.sh -json "$OUT" \
			-label machine="$MACHINE" -label seq="$seq" -label load1="$l" -label commit="$COMMIT" \
			-label VARIANT="$VARIANT" -label SYNC="$SYNC" $labels </dev/null >"bin/perf-sweep.last" 2>&1
		st=$?
		grep -E "^(delivery latency|PASS|FAIL)" bin/perf-sweep.last | tr '\n' ' '
		echo "exit $st"
		if [ "$st" -ne 0 ] && ! grep -q "check(s) failed" bin/perf-sweep.last; then
			echo "sweep: run $seq broke (not a threshold miss); log follows" >&2
			tail -n 15 bin/perf-sweep.last >&2
		fi
	)
done
docker exec "$PG_CONTAINER" psql -qX -U klacks -d klacks \
	-c "ALTER SYSTEM RESET synchronous_commit" -c "SELECT pg_reload_conf()" >/dev/null
echo "sweep: done, $seq runs -> $OUT"
