#!/usr/bin/env python3
"""Follow a Zeek JSON log and yield records as they are written."""
import argparse, json, time
from pathlib import Path


def follow(path, from_start=True, poll=0.2, idle_timeout=None):
    """Yield dicts from a Zeek JSON log, waiting for new lines as they arrive."""
    path = Path(path)
    while not path.exists():
        time.sleep(poll)
    with path.open("r") as f:
        if not from_start:
            f.seek(0, 2)
        idle = 0.0
        while True:
            line = f.readline()
            if line:
                idle = 0.0
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
            else:
                if idle_timeout is not None and idle >= idle_timeout:
                    return
                time.sleep(poll)
                idle += poll


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--log", required=True)
    p.add_argument("--stats-every", type=int, default=2000)
    p.add_argument("--idle-timeout", type=float, default=3.0)
    p.add_argument("--show", type=int, default=3)
    a = p.parse_args()

    start = time.time()
    n = 0
    for rec in follow(a.log, idle_timeout=a.idle_timeout):
        n += 1
        if n <= a.show:
            print(f"  sample {n}: {rec.get('id.orig_h')} -> "
                  f"{rec.get('id.resp_h')}:{rec.get('id.resp_p')} "
                  f"proto={rec.get('proto')} service={rec.get('service')}")
        if n % a.stats_every == 0:
            el = time.time() - start
            print(f"  {n} records, {el:.1f}s elapsed, {n/el:.0f} rec/s")

    el = time.time() - start
    print(f"\ndone: {n} records in {el:.1f}s ({n/max(el,1e-9):.0f} rec/s)")


if __name__ == "__main__":
    main()
