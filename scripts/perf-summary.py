#!/usr/bin/env python3
"""Summarize perf-sweep JSONL datasets (S-54) as Markdown tables.

    scripts/perf-summary.py perf-data/*.jsonl

Runs are grouped by machine, variant, synchronous_commit, pool, rooms and
target rate. Each cell is the median over the group's runs with the
min-max range; a group is "sustained" only if every run passed the gate.
Server quantiles are histogram bucket upper bounds (buckets double from
0.5 ms), so they are coarse. Standard library only.
"""
import json
import statistics
import sys
from collections import defaultdict


def key(r):
    l = r.get("labels", {})
    return (
        l.get("machine", "?"),
        l.get("VARIANT", "base"),
        l.get("SYNC", "on"),
        int(l.get("PERF_POOL", 60)),
        r["rooms"],
        r["rate"],
    )


def cell(vals, fmt="{:.1f}"):
    if not vals:
        return "-"
    m = statistics.median(vals)
    if len(vals) == 1 or min(vals) == max(vals):
        return fmt.format(m)
    return f"{fmt.format(m)} ({fmt.format(min(vals))}-{fmt.format(max(vals))})"


def main(paths):
    groups = defaultdict(list)
    for p in paths:
        with open(p) as f:
            for line in f:
                if line.strip():
                    r = json.loads(line)
                    groups[key(r)].append(r)
    cols = ["machine", "variant", "sync", "pool", "conns", "rate/s", "achieved/s", "runs", "pass",
            "p50 ms", "p95 ms", "p99 ms", "max ms", "lock p50<=", "lock p99<=", "pool peak", "delivered %"]
    print("| " + " | ".join(cols) + " |")
    print("|" + "---|" * len(cols))
    for k in sorted(groups):
        rs = groups[k]
        machine, variant, sync, pool, rooms, rate = k
        passed = sum(r["pass"] for r in rs)
        delivered = [100.0 * r["delivered"] / r["expected"] for r in rs if r["expected"]]
        row = [
            machine, variant, sync, str(pool), str(rooms * rs[0]["members"]), f"{rate:g}",
            cell([r["sent"] / r["duration_s"] for r in rs], "{:.0f}"),
            str(len(rs)), f"{passed}/{len(rs)}",
            cell([r["p50_ms"] for r in rs]), cell([r["p95_ms"] for r in rs]),
            cell([r["p99_ms"] for r in rs]), cell([r["max_ms"] for r in rs], "{:.0f}"),
            cell([r["lock_p50_ms"] for r in rs], "{:g}"), cell([r["lock_p99_ms"] for r in rs], "{:g}"),
            cell([r["pool_peak"] for r in rs], "{:.0f}"), cell(delivered, "{:.2f}"),
        ]
        print("| " + " | ".join(row) + " |")


if __name__ == "__main__":
    main(sys.argv[1:])
