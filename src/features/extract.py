#!/usr/bin/env python3
"""Stream a Zeek conn.log through the window and score every source."""
import argparse, sys, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ingest.log_stream import follow
from features.window import SlidingWindow, FlowRecord
from features.compute import features_for


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--log", required=True)
    p.add_argument("--span", type=float, default=300.0)
    p.add_argument("--idle-timeout", type=float, default=3.0)
    p.add_argument("--top", type=int, default=10)
    a = p.parse_args()

    win = SlidingWindow(span=a.span)
    latest = {}
    n = 0
    start = time.time()

    for rec in follow(a.log, idle_timeout=a.idle_timeout):
        f = FlowRecord(rec)
        if not f.src:
            continue
        flows = win.add(f)
        n += 1
        if n % 200 == 0:
            row = features_for(f.src, list(flows), a.span)
            if row:
                latest[f.src] = row
        if n % 20000 == 0:
            win.evict_idle()

    for src, flows in win.by_src.items():
        row = features_for(src, list(flows), a.span)
        if row:
            latest[src] = row

    el = time.time() - start
    print(f"{n} flows processed, {len(latest)} sources tracked, {el:.1f}s\n")

    print(f"{'source':<16}{'flows':>7}{'ports':>7}{'hosts':>7}"
          f"{'fail%':>7}{'out/in':>9}{'bcv':>7}{'period':>8}")
    print("-" * 68)
    for row in sorted(latest.values(), key=lambda r: r["n_flows"], reverse=True)[:a.top]:
        bcv = row.get("beacon_cv")
        per = row.get("beacon_period")
        print(f"{row['src']:<16}{row['n_flows']:>7}{row['n_dst_ports']:>7}"
              f"{row['n_dst_hosts']:>7}{row['failed_ratio']*100:>6.0f}%"
              f"{row['out_in_ratio']:>9.2f}"
              f"{(f'{bcv:.2f}' if bcv is not None else '-'):>7}"
              f"{(f'{per:.0f}s' if per is not None else '-'):>8}")


if __name__ == "__main__":
    main()
