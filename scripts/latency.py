#!/usr/bin/env python3
"""Detection latency: how long after the sensor emitted a record did the alert
derived from it exist in the store.

Why not simply `detected_at - ts`. An alert carries two clocks and they are
not the same clock. `ts` is traffic time, read from the capture; `detected_at`
is wall time, read from the system. Subtracting them on the 2011 Neris capture
gives about fifteen years. The two are kept side by side so the gap can be
computed against a known feed schedule, which is what this script does — not
so they can be subtracted directly.

During a paced replay the feeder is the sensor, so it knows exactly when each
record was handed over. `dashboard/replay.py --trace` writes that out as
data/replay/feed_trace.jsonl. Joining it to the alerts table:

    latency = alert.detected_at - feed_wall(triggering record)

The triggering record is the last record of that alert's kind with ts <= the
alert's ts, because every detector stamps its alert with its own traffic clock
at the moment it fires, and that clock is the newest record it has seen.

Reported as a distribution. A mean would hide exactly the thing worth seeing:
the stall is a small number of very long waits, not a shift in the middle.

    python3 scripts/latency.py
    python3 scripts/latency.py --db data/alerts.db --trace data/replay/feed_trace.jsonl
"""
import argparse
import bisect
import json
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Which log each threat class is derived from. The detectors take disjoint
# inputs, so this mapping is exact rather than a guess.
KIND_OF = {
    "port_scan": "conn", "ddos": "conn", "exfiltration": "conn",
    "c2_beacon": "conn", "dga_domain": "dns", "dns_tunnel": "dns",
    "encrypted_malware": "ssl",
}


def load_trace(path):
    """kind -> (climb_ts, climb_wall): when this log's traffic clock advanced.

    Every detector stamps its alert with its own traffic clock, and that clock
    is a running maximum of the record timestamps it has been handed. So the
    instant that matters for an alert at traffic time A is when the *delivered*
    traffic clock first reached A.

    That is not the same as "when every record with ts <= A had arrived", and
    the difference is not small. Zeek appends a connection when it closes, so
    the feeder paces on `ts + duration` (finding #11): a connection that opened
    at the start of the Neris capture and closed at the end is written last,
    while carrying one of the earliest timestamps. Keying on "everything up to
    A" therefore waits for that straggler and reports latencies of -196 s.

    Read in feed order and keep the points where the running max stepped up.
    """
    climb = defaultdict(lambda: ([], []))
    peak = defaultdict(lambda: float("-inf"))
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind, ts, w = r["kind"], float(r["ts"]), float(r["w"])
            if ts > peak[kind]:
                peak[kind] = ts
                climb[kind][0].append(ts)
                climb[kind][1].append(w)
    return dict(climb)


def fed_at(trace, kind, ts):
    """Wall clock at which this log's delivered traffic clock reached ts."""
    if kind not in trace:
        return None
    times, walls = trace[kind]
    i = bisect.bisect_left(times, ts)
    if i >= len(times):
        return None          # the clock never got this far — nothing to compare
    return walls[i]


def pct(values, p):
    if not values:
        return float("nan")
    k = (len(values) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (k - lo)


def histogram(values, width=48):
    if not values:
        return []
    edges = [0.0, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, float("inf")]
    labels, counts = [], []
    for lo, hi in zip(edges, edges[1:]):
        n = sum(1 for v in values if lo <= v < hi)
        labels.append(f"{lo:g}" + ("+" if hi == float("inf") else f"-{hi:g}"))
        counts.append(n)
    top = max(counts) or 1
    rows = []
    for lab, n in zip(labels, counts):
        bar = "#" * int(round(width * n / top))
        rows.append(f"  {lab:>10s}s  {n:6d}  {bar}")
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default=str(ROOT / "data" / "alerts.db"))
    p.add_argument("--trace", default=str(ROOT / "data" / "replay" / "feed_trace.jsonl"))
    p.add_argument("--label", default="", help="tag for the printed heading")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    a = p.parse_args()

    if not Path(a.trace).exists():
        print(f"no feed trace at {a.trace}\n"
              "Run a replay with trace=1 first, e.g.\n"
              "  curl -X POST 'localhost:8000/api/replay/start"
              "?pcap=data/raw/botnet/botnet-capture-20110811-neris.pcap"
              "&speed=60&trace=1'", file=sys.stderr)
        return 2
    if not Path(a.db).exists():
        print(f"no alert database at {a.db}", file=sys.stderr)
        return 2

    trace = load_trace(a.trace)
    db = sqlite3.connect(a.db)
    db.row_factory = sqlite3.Row
    rows = [dict(r) for r in db.execute(
        "SELECT ts, detected_at, threat_class, detector FROM alerts ORDER BY id")]
    db.close()

    per_detector = defaultdict(list)
    lats, unmatched = [], 0
    for r in rows:
        kind = KIND_OF.get(r["threat_class"])
        w = fed_at(trace, kind, r["ts"]) if kind else None
        if w is None:
            unmatched += 1
            continue
        lat = r["detected_at"] - w
        lats.append(lat)
        per_detector[r["threat_class"]].append(lat)

    lats.sort()
    out = {
        "label": a.label,
        "alerts": len(rows),
        "matched": len(lats),
        "unmatched": unmatched,
        "p50": round(pct(lats, 50), 3) if lats else None,
        "p90": round(pct(lats, 90), 3) if lats else None,
        "p99": round(pct(lats, 99), 3) if lats else None,
        "max": round(lats[-1], 3) if lats else None,
        "min": round(lats[0], 3) if lats else None,
    }

    if a.json:
        out["per_class"] = {
            k: {"n": len(v), "p50": round(pct(sorted(v), 50), 3),
                "max": round(max(v), 3)}
            for k, v in sorted(per_detector.items())}
        print(json.dumps(out))
        return 0

    head = f"detection latency{' — ' + a.label if a.label else ''}"
    print(head)
    print("=" * len(head))
    print(f"alerts {out['alerts']}, matched to a fed record {out['matched']}"
          f"{f', unmatched {unmatched}' if unmatched else ''}\n")
    if not lats:
        print("nothing to report")
        return 1

    print(f"  min  {out['min']:8.3f}s")
    print(f"  p50  {out['p50']:8.3f}s")
    print(f"  p90  {out['p90']:8.3f}s")
    print(f"  p99  {out['p99']:8.3f}s")
    print(f"  max  {out['max']:8.3f}s")
    print("\ndistribution")
    for row in histogram(lats):
        print(row)

    print("\nper threat class")
    for k, v in sorted(per_detector.items(), key=lambda kv: -max(kv[1])):
        v = sorted(v)
        print(f"  {k:20s} n={len(v):5d}  p50 {pct(v,50):7.3f}s  "
              f"p99 {pct(v,99):7.3f}s  max {v[-1]:7.3f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
