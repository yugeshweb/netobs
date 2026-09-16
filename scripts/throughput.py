#!/usr/bin/env python3
"""Measure how fast the pipeline consumes arriving records, and where it stops
keeping up.

The pipeline reads Zeek logs another process appends to. If it is slower than
the writer, nothing is lost -- a backlog builds and it falls behind. So
"keeping up at rate R" means the backlog stays flat rather than growing.

Backlog is read straight out of /proc/<pid>/fdinfo: the pipeline's own file
offset against what the feeder has written. Nothing in src/ is instrumented
or modified. Buffered reads mean the offset leads true progress by up to one
buffer (~8 KB, about 15 records); that is a constant, so it does not affect
whether the backlog grows.

modes
  saturate    feed everything as fast as possible; the pipeline's steady-state
              consumption rate is its capacity
  rate        feed at a constant records/sec and see whether backlog holds flat
  occupancy   no pipeline; report how many flows a per-source window actually
              holds, which is what features_for() walks
"""
import argparse
import bisect
import json
import os
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / "data" / "replay" / "live"
KINDS = ("conn.log", "dns.log", "ssl.log")
SAMPLE_EVERY = 0.25


# ---------------------------------------------------------------- loading

def load_records(logdir, limit=None, only=None):
    """Records in Zeek write order, interleaved across logs as they arrived.

    Same ordering rule as the replay feeder: a log is in write order, not
    timestamp order, so pace on ts + duration forced non-decreasing.
    """
    logdir = Path(logdir)
    wanted = KINDS if not only else tuple(
        k if k.endswith(".log") else k + ".log" for k in only.split(","))
    out = []
    for kind in wanted:
        f = logdir / kind
        if not f.exists():
            continue
        emit = None
        for line in f.open():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rec = json.loads(line)
                wrote = float(rec.get("ts", 0.0)) + float(rec.get("duration") or 0.0)
            except (ValueError, TypeError, AttributeError):
                continue
            emit = wrote if emit is None else max(emit, wrote)
            out.append((emit, kind, line))
    out.sort(key=lambda r: r[0])
    if limit:
        out = out[:limit]
    return out


# ------------------------------------------------------------- occupancy

def occupancy(records, span):
    """How many flows the per-source window holds when features_for() runs.

    The pipeline computes features every 25th conn record, over the window
    for that one source -- so this, not the total record rate, is what sets
    the cost per record.
    """
    by_src = defaultdict(deque)
    now = 0.0
    n_conn = 0
    sizes = []
    for _, kind, line in records:
        if kind != "conn.log":
            continue
        rec = json.loads(line)
        ts = float(rec.get("ts", 0.0))
        src = rec.get("id.orig_h", "")
        if ts > now:
            now = ts
        q = by_src[src]
        q.append(ts)
        cutoff = now - span
        while q and q[0] < cutoff:
            q.popleft()
        n_conn += 1
        if n_conn % 25 == 0:
            sizes.append(len(q))
    sizes.sort()
    if not sizes:
        return {}
    pick = lambda p: sizes[min(len(sizes) - 1, int(p * len(sizes)))]
    return {
        "samples": len(sizes),
        "mean": round(sum(sizes) / len(sizes), 1),
        "p50": pick(0.50), "p90": pick(0.90), "p99": pick(0.99),
        "max": sizes[-1],
        "distinct_sources": len(by_src),
    }


# ----------------------------------------------------------- /proc probe

class Probe:
    """Follows the pipeline's read offset in each live log."""

    def __init__(self, pid, offsets):
        self.pid = pid
        self.offsets = offsets            # kind -> [cumulative byte offset]
        self.want = set(offsets)
        self.fds = {}
        self.high = {k: 0 for k in offsets}

    def _find_fds(self):
        base = Path(f"/proc/{self.pid}/fd")
        try:
            entries = list(base.iterdir())
        except OSError:
            return
        for e in entries:
            try:
                target = os.readlink(e)
            except OSError:
                continue
            name = Path(target).name
            if name in KINDS and Path(target).parent.name == "live":
                self.fds[name] = e.name

    def read(self):
        """Records the pipeline has read, per kind."""
        # the pipeline opens its logs a couple of seconds in, after the
        # model loads, so keep looking until every one is accounted for
        if set(self.fds) != self.want:
            self._find_fds()
        # A generator that reaches StopIteration closes its file, the fd
        # goes away and its number gets reused, so a raw reading can drop to
        # zero or point at something else. A read position only ever moves
        # forward, so keep the high-water mark.
        for kind, fd in self.fds.items():
            try:
                with open(f"/proc/{self.pid}/fdinfo/{fd}") as f:
                    pos = int(f.readline().split()[1])
            except (OSError, ValueError, IndexError):
                continue
            n = bisect.bisect_right(self.offsets[kind], pos)
            if n > self.high[kind]:
                self.high[kind] = n
        return dict(self.high)

    def rss_mb(self):
        try:
            with open(f"/proc/{self.pid}/statm") as f:
                return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 1e6
        except (OSError, ValueError, IndexError):
            return 0.0


# ------------------------------------------------------------------- run

def run(args):
    records = load_records(args.logdir, args.limit, args.kinds)
    if not records:
        print("no records found", file=sys.stderr)
        return 2
    kinds = sorted({k for _, k, _ in records})

    LIVE.mkdir(parents=True, exist_ok=True)
    for f in list(LIVE.glob("*.log")) + list(LIVE.glob("*.done")):
        f.unlink()

    # byte offset of the end of each record, per log, so a /proc read
    # position maps back to an exact record count
    offsets = {k: [] for k in kinds}
    running = {k: 0 for k in kinds}
    for _, kind, line in records:
        running[kind] += len(line) + 1
        offsets[kind].append(running[kind])

    handles = {k: (LIVE / k).open("a") for k in kinds}

    db = ROOT / "data" / "throughput.db"
    # a previous run killed mid-commit leaves a journal behind, and sqlite
    # then fails the next commit with "disk I/O error"
    for f in (db, db.with_name(db.name + "-journal")):
        if f.exists():
            f.unlink()
    cmd = [sys.executable, "-u", "src/pipeline.py",
           "--logdir", str(LIVE.relative_to(ROOT)),
           "--db", str(db.relative_to(ROOT)),
           "--span", str(args.span),
           "--quiet", "--idle-timeout", str(args.idle_timeout)]
    if args.no_pipeline:
        # control: how fast the feeder alone can write, so we know the
        # ceiling any pipeline reading is measured against
        log, proc, probe = None, None, None
    else:
        log = open(ROOT / "data" / "throughput_pipeline.log", "w")
        proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=log,
                                stderr=subprocess.STDOUT)
        probe = Probe(proc.pid, offsets)

    trace = []
    stop = threading.Event()
    written = {"n": 0}

    def sample():
        t0 = time.time()
        while not stop.is_set():
            done = probe.read() if probe else {}
            trace.append({
                "t": round(time.time() - t0, 3),
                "written": written["n"],
                "read": sum(done.values()),
                "per_kind": dict(done),
                "fds": dict(probe.fds) if probe else {},
                "rss_mb": round(probe.rss_mb(), 1) if probe else 0.0,
            })
            time.sleep(SAMPLE_EVERY)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()

    # -- feed -------------------------------------------------------------
    total = len(records)
    rate = args.rate
    # batch writes into ~20ms chunks; flushing per record is a feeder cost,
    # not a pipeline cost, and would cap the rate well below what we test
    batch = 1 if not rate else max(1, min(2000, int(rate * 0.02)))
    feed_start = time.time()
    i = 0
    while i < total:
        chunk = records[i:i + batch]
        for _, kind, line in chunk:
            handles[kind].write(line + "\n")
        for k in {c[1] for c in chunk}:
            handles[k].flush()
        i += len(chunk)
        written["n"] = i
        if rate:
            target = feed_start + i / rate
            now = time.time()
            if target > now:
                time.sleep(target - now)
    feed_wall = time.time() - feed_start
    for h in handles.values():
        h.close()
    # Tell the pipeline the feed is over instead of making it wait out a
    # timeout to infer it. Written after every handle is closed, so the marker
    # only appears once the data is on disk. Without this the tail sits in the
    # measurement as dead time that has nothing to do with throughput.
    for k in kinds:
        (LIVE / f"{k}.done").write_text("")

    # -- wait for the pipeline to drain -----------------------------------
    if proc is None:
        stop.set()
        sampler.join(timeout=2)
        return report(args, records, kinds, trace, feed_wall, None, "")

    # Wait on progress, not on a fixed budget: at rates near capacity the
    # backlog can take far longer to work off than any constant allows, and
    # killing the pipeline early truncates the measurement.
    patience = len(kinds) * args.idle_timeout + 45
    last_read, last_move = -1, time.time()
    while proc.poll() is None:
        now = sum(probe.read().values())
        if now != last_read:
            last_read, last_move = now, time.time()
        elif time.time() - last_move > patience:
            break
        time.sleep(0.25)
    if proc.poll() is None:
        proc.terminate()
    proc.wait(timeout=10)
    stop.set()
    sampler.join(timeout=2)
    log.close()

    # the pipeline's own tally, from its stdout
    tail = (ROOT / "data" / "throughput_pipeline.log").read_text()
    processed = None
    for line in tail.splitlines():
        if line.startswith("records:") and "total=" in line:
            processed = int(line.split("total=")[1].split()[0])

    return report(args, records, kinds, trace, feed_wall, processed, tail)


def report(args, records, kinds, trace, feed_wall, processed, tail):
    total = len(records)
    feed_rate = total / feed_wall if feed_wall else 0

    # The pipeline spends its first seconds importing lightgbm and loading
    # the DGA model; counting that as throughput would understate it. So
    # measure only while it is actually consuming -- after the first record
    # is read, before it has caught up with everything fed -- and drop the
    # first fifth of that as ramp.
    first_read = next((s["t"] for s in trace if s["read"] > 0), None)
    startup = first_read
    active = [s for s in trace if 0 < s["read"] < total]

    # Whether it keeps up can only be judged while records are still
    # arriving. Measuring past the end of the feed folds in the catch-up,
    # which makes a run that fell badly behind look like it held level.
    feeding = [s for s in active if s["written"] < total]
    steady = feeding[int(len(feeding) * 0.2):] if len(feeding) > 5 else feeding
    if len(steady) < 2:
        steady = active[int(len(active) * 0.2):] if len(active) > 5 else active
    if len(steady) < 2:
        steady = active or trace

    # In saturate mode the feeder is not the limiter, so the time taken to
    # get through everything is the pipeline's capacity outright.
    #
    # The sampler reads the pipeline's file position from /proc, so it can
    # only observe completion while the process is still alive. That used to
    # be free: the pipeline sat out an idle timeout at the end and there were
    # seconds of samples showing read == total. Now the .done markers let it
    # exit as soon as it has finished, and the last sample can land before the
    # final records are counted -- which reported capacity as 0 rather than as
    # unmeasured. Fall back to the last observation when the run is known to
    # have processed everything.
    capacity = 0.0
    if first_read is not None:
        done_t = next((s["t"] for s in trace if s["read"] >= total), None)
        if done_t is None and processed is not None and processed >= total and trace:
            done_t = trace[-1]["t"]
        if done_t and done_t > first_read:
            capacity = total / (done_t - first_read)

    # merged() follows each log with its own generator and advances them
    # one at a time, so when a sparse log is exhausted it blocks on that one
    # for a whole idle_timeout and the pipeline processes nothing meanwhile.
    # Separate the time it spent working from the time it spent stalled.
    worked_dt = worked_dn = stalled = 0.0
    window = [s for s in trace
              if first_read is not None and s["t"] >= first_read]
    for a, b in zip(window, window[1:]):
        dt, dn = b["t"] - a["t"], b["read"] - a["read"]
        if a["read"] >= total:
            break
        if dn > 0:
            worked_dt += dt
            worked_dn += dn
        else:
            stalled += dt
    working = worked_dn / worked_dt if worked_dt else 0.0

    consume = 0.0
    if len(steady) >= 2:
        dt = steady[-1]["t"] - steady[0]["t"]
        dn = steady[-1]["read"] - steady[0]["read"]
        consume = dn / dt if dt > 0 else 0.0

    backlogs = [s["written"] - s["read"] for s in steady]
    slope = 0.0
    if len(steady) >= 2:
        dt = steady[-1]["t"] - steady[0]["t"]
        slope = (backlogs[-1] - backlogs[0]) / dt if dt > 0 else 0.0

    peak_rss = max((s["rss_mb"] for s in trace), default=0.0)
    result = {
        "label": args.label,
        "startup_s": round(startup, 2) if startup is not None else None,
        "steady_window_s": (round(steady[-1]["t"] - steady[0]["t"], 1)
                            if len(steady) >= 2 else 0.0),
        "logdir": str(args.logdir),
        "mode": "saturate" if not args.rate else "rate",
        "span": args.span,
        "kinds_fed": args.kinds or "all",
        "records": total,
        "kinds": kinds,
        "target_rate": args.rate,
        "feed_rate": round(feed_rate, 1),
        "feed_wall_s": round(feed_wall, 1),
        "consume_rate": round(consume, 1),
        "capacity_rate": round(capacity, 1),
        "working_rate": round(working, 1),
        "stalled_s": round(stalled, 1),
        "backlog_start": backlogs[0] if backlogs else 0,
        "backlog_end": backlogs[-1] if backlogs else 0,
        "backlog_max": max(backlogs) if backlogs else 0,
        "backlog_slope_rec_per_s": round(slope, 1),
        "judged_while_feeding": len(feeding) > 5,
        "keeps_up": bool(slope < max(50.0, 0.02 * (args.rate or 0))),
        "peak_rss_mb": round(peak_rss, 1),
        "processed": processed,
        "complete": processed == total,
    }
    if args.trace:
        Path(args.trace).write_text("\n".join(json.dumps(s) for s in trace))
    print(json.dumps(result))
    if args.verbose:
        print(tail.strip(), file=sys.stderr)
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--logdir", required=True)
    p.add_argument("--rate", type=float, default=0.0,
                   help="records/sec; 0 means saturate (feed as fast as possible)")
    p.add_argument("--limit", type=int, default=0,
                   help="use only the first N records")
    p.add_argument("--span", type=float, default=300.0,
                   help="pipeline sliding-window span, seconds")
    p.add_argument("--idle-timeout", type=float, default=10.0)
    p.add_argument("--label", default="")
    p.add_argument("--occupancy", action="store_true",
                   help="report per-source window occupancy and exit")
    p.add_argument("--no-pipeline", action="store_true",
                   help="feeder only, to find the write ceiling")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--trace", default="", help="write raw samples here")
    p.add_argument("--kinds", default="",
                   help="restrict to these logs, e.g. conn. A sparse log that "
                        "goes quiet stalls merged() for a whole idle_timeout, "
                        "which corrupts a throughput reading.")
    a = p.parse_args()

    if a.occupancy:
        recs = load_records(a.logdir, a.limit, a.kinds)
        out = occupancy(recs, a.span)
        out.update({"logdir": str(a.logdir), "span": a.span,
                    "records": len(recs)})
        print(json.dumps(out))
        return 0
    return run(a)


if __name__ == "__main__":
    sys.exit(main())
