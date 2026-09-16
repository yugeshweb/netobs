#!/usr/bin/env python3
"""NetObs pipeline: read-only ingest -> features -> detection -> incidents.

Reads Zeek logs as they are written, merges them in traffic-clock order, runs
every detector over the shared state, and folds alerts into incidents.

Read-only by construction: the only inputs are log files another process
writes. Nothing here can contact, probe or block anything on the network.
"""
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ingest.log_stream import follow, IDLE
from features.window import SlidingWindow, FlowRecord
from features.compute import features_for
from detectors.port_scan import PortScanDetector
from detectors.ddos import DDoSDetector
from detectors.exfiltration import ExfiltrationDetector
from detectors.beaconing import BeaconDetector
from detectors.dns_threat import DNSDetector
from detectors.encrypted_threat import EncryptedThreatDetector
from alerts.aggregator import IncidentAggregator, incident_key
from alerts.store import AlertStore


def merged(paths, lag=0.5, quiet_timeout=10.0, poll=0.05):
    """Yield (kind, record) from several logs, ordered by timestamp.

    A k-way merge can only guarantee timestamp order while every input has a
    record waiting: until a log speaks, there is no way to know whether its
    next record belongs before the ones already in hand. The old version took
    that literally and blocked on each log in turn, so a single quiet log
    stopped the pipeline for a whole timeout while the others sat unread.

    This version bounds the wait instead. A silent log gets `lag` seconds to
    speak; past that its siblings are released and it rejoins the ordering
    whenever it next produces something. Latency is therefore bounded by `lag`
    rather than by the timeout that decides a log is finished — those are now
    two different numbers, which is the whole point.

    What that costs: strict cross-log ordering, but only while a log is quiet.
    It is safe here because the three kinds drive disjoint detector state —
    conn feeds the window, DDoS, beaconing, scanning and exfiltration; dns
    only DNSDetector; ssl only EncryptedThreatDetector. No detector reads
    another kind's records, so interleaving cannot change which alerts fire,
    only the order they reach the audit trail.

    A log ends when its `<log>.done` marker appears and it has been read out,
    or after `quiet_timeout` without a line for a sensor that offers no
    marker. Either way one log ending no longer holds up the rest.
    """
    # No per-log idle timeout. A log going quiet must never be what ends it:
    # ssl.log in Neris has a 2390s internal gap, 40s of wall silence at 60x,
    # and any per-log timeout shorter than that silently drops every later TLS
    # session. The marker decides when a log is finished; quiet_timeout below
    # is a single global fallback for when nothing arrives on *any* log.
    gens, pending, quiet_since = {}, {}, {}
    for kind, p in paths.items():
        if Path(p).exists():
            gens[kind] = follow(p, block=False, done_marker=True)

    last_record = time.time()
    while gens or pending:
        now = time.time()

        # Top up every log that has no record in hand. Each of these is one
        # readline; none of them can block.
        for kind in list(gens):
            if kind in pending:
                continue
            try:
                rec = next(gens[kind])
            except StopIteration:
                del gens[kind]
                quiet_since.pop(kind, None)
                continue
            if rec is IDLE:
                quiet_since.setdefault(kind, now)
            else:
                pending[kind] = rec
                quiet_since.pop(kind, None)
                last_record = now

        if not pending:
            if not gens:
                return
            if time.time() - last_record >= quiet_timeout:
                return
            time.sleep(poll)
            continue

        # Hold back only while a log that owes us a record might still be
        # about to produce one. Once every silent log has been silent for
        # `lag`, go without them.
        waiting = [k for k in gens if k not in pending]
        if waiting:
            newest_silence = max(quiet_since.get(k, now) for k in waiting)
            if now - newest_silence < lag:
                time.sleep(poll)
                continue

        kind = min(pending, key=lambda k: float(pending[k].get("ts", 0.0) or 0.0))
        yield kind, pending.pop(kind)


class Pipeline:
    def __init__(self, logdir, model_dir, db_path, span=300.0,
                 reset_db=True, quiet=False):
        self.logdir = Path(logdir)
        self.span = span
        self.quiet = quiet

        self.window = SlidingWindow(span=span)
        self.scan = PortScanDetector()
        self.ddos = DDoSDetector()
        self.exfil = ExfiltrationDetector()
        self.beacon = BeaconDetector()
        self.dns = DNSDetector(str(Path(model_dir) / "dga_model.joblib"))
        self.tls = EncryptedThreatDetector()

        self.agg = IncidentAggregator()
        self.store = AlertStore(db_path, reset=reset_db)

        self.counts = {"conn": 0, "dns": 0, "ssl": 0}
        self._printed = {}
        self.alerts = 0
        self.feature_every = 25

    def _emit(self, alert):
        self.alerts += 1
        key = incident_key(alert)
        self.store.write_alert(alert, key)
        event, inc = self.agg.add(alert)
        if not event:
            return
        self.store.upsert_incident(inc)
        if self.quiet:
            return
        # Print new incidents and genuine escalations only. Routine updates
        # go to the database silently; the console is not the dashboard.
        prev = self._printed.get(inc.key)
        if event == "new":
            print(f"  NEW {inc.summary()}", flush=True)
            self._printed[inc.key] = inc.severity
        elif prev != inc.severity:
            print(f"  ESC {inc.summary()}", flush=True)
            self._printed[inc.key] = inc.severity

    def on_conn(self, rec):
        f = FlowRecord(rec)
        if not f.src:
            return
        flows = self.window.add(f)
        self.counts["conn"] += 1

        key, target_flows = self.ddos.add(f)
        if self.counts["conn"] % 20 == 0:
            a = self.ddos.check(key, target_flows)
            if a:
                self._emit(a)

        bkey = self.beacon.add(f)
        if bkey is not None and self.counts["conn"] % 50 == 0:
            a = self.beacon.check(bkey)
            if a:
                self._emit(a)

        if self.counts["conn"] % self.feature_every:
            return

        row = features_for(f.src, list(flows), self.span)
        if not row:
            return
        for a in (self.scan.check(row),
                  self.exfil.check(f.src, list(flows), self.window.now)):
            if a:
                self._emit(a)

        if self.counts["conn"] % 20000 == 0:
            self.window.evict_idle()
            self.agg.expire()

    def on_dns(self, rec):
        self.counts["dns"] += 1
        src, queries = self.dns.add_query(rec)
        if src and self.counts["dns"] % 10 == 0:
            a = self.dns.check_tunnel(src, list(queries))
            if a:
                self._emit(a)
        a = self.dns.check_domain(rec)
        if a:
            self._emit(a)

    def on_ssl(self, rec):
        self.counts["ssl"] += 1
        self.tls.observe(rec)
        a = self.tls.check(rec)
        if a:
            self._emit(a)

    def _final_sweep(self):
        """Run the sampled window detectors once more, at end of stream.

        Same checks as the periodic path in on_conn, but over every source
        still in the window rather than only the one whose connection just
        arrived. This is what lets a short capture (fewer connections than
        feature_every) produce an alert at all.
        """
        for src in list(self.window.by_src):
            flows = list(self.window.window_for(src))
            if not flows:
                continue
            row = features_for(src, flows, self.span)
            if row:
                a = self.scan.check(row)
                if a:
                    self._emit(a)
            a = self.exfil.check(src, flows, self.window.now)
            if a:
                self._emit(a)

    def run(self, lag=0.5, quiet_timeout=10.0):
        paths = {"conn": self.logdir / "conn.log",
                 "dns": self.logdir / "dns.log",
                 "ssl": self.logdir / "ssl.log"}
        handlers = {"conn": self.on_conn, "dns": self.on_dns, "ssl": self.on_ssl}

        start = time.time()
        first_read = last_read = None
        for kind, rec in merged(paths, lag=lag, quiet_timeout=quiet_timeout):
            if first_read is None:
                first_read = time.time()
            handlers[kind](rec)
            last_read = time.time()

        # The window-feature detectors (scan, exfil) only run every
        # feature_every-th connection, so a capture that ends mid-interval --
        # or is shorter than the interval, like the 21-record exfil capture --
        # would never have its final window evaluated at all. Sweep once at
        # end of stream over every source still in the window. Cooldowns still
        # apply, so anything already reported does not re-fire; this only
        # recovers detections that the sampling gate would otherwise drop.
        self._final_sweep()

        # Close only what genuinely went quiet; leave the rest open so the
        # dashboard can distinguish active incidents from resolved ones.
        self.agg.expire()
        for inc in self.agg.all_incidents():
            self.store.upsert_incident(inc)
        self.store.flush()

        # From the first record to the last, not wall time minus a timeout.
        # The old form subtracted exactly one idle_timeout while merged()
        # waited out one per log, which is why the same run over the same data
        # reported 5,807, 3,152 and 1,602 records/s at three different
        # timeouts. Measuring the working interval removes the knob from the
        # answer: the startup wait and the final quiet wait are not work.
        elapsed = (last_read - first_read) if first_read and last_read else 0.0
        return elapsed, start


def main():
    p = argparse.ArgumentParser(description="NetObs detection pipeline")
    p.add_argument("--logdir", required=True, help="directory of Zeek JSON logs")
    p.add_argument("--models", default="data/models")
    p.add_argument("--db", default="data/alerts.db")
    p.add_argument("--span", type=float, default=300.0)
    p.add_argument("--lag", type=float, default=0.5,
                   help="how long a quiet log may hold up its siblings; this "
                        "is the latency bound")
    p.add_argument("--quiet-timeout", type=float, default=10.0,
                   help="silence after which a log with no .done marker is "
                        "treated as finished")
    p.add_argument("--idle-timeout", type=float, default=None,
                   help="deprecated alias for --quiet-timeout")
    p.add_argument("--keep-db", action="store_true")
    p.add_argument("--quiet", action="store_true")
    a = p.parse_args()

    # --idle-timeout used to mean both "wait this long before giving up on a
    # log" and, as a side effect, "stall everything for this long". It now
    # only means the first, so it maps onto --quiet-timeout.
    quiet_timeout = a.idle_timeout if a.idle_timeout is not None else a.quiet_timeout

    pipe = Pipeline(a.logdir, a.models, a.db, span=a.span,
                    reset_db=not a.keep_db, quiet=a.quiet)
    print(f"reading {a.logdir}\n")
    elapsed, _ = pipe.run(lag=a.lag, quiet_timeout=quiet_timeout)

    total = sum(pipe.counts.values())
    print(f"\nrecords: {pipe.counts}  total={total}")
    print(f"alerts: {pipe.alerts}")
    print(f"incidents: {pipe.agg.stats()}")
    print(f"stored: {pipe.store.counts()}")
    if elapsed > 0:
        print(f"elapsed {elapsed:.1f}s ({total/elapsed:,.0f} records/s)")
    pipe.store.close()


if __name__ == "__main__":
    main()
