#!/usr/bin/env python3
"""NetObs pipeline: read-only ingest -> features -> detection -> incidents.

Reads Zeek logs as they are written, merges them in traffic-clock order, runs
every detector over the shared state, and folds alerts into incidents.

Read-only by construction: the only inputs are log files another process
writes. Nothing here can contact, probe or block anything on the network.
"""
import argparse
import heapq
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ingest.log_stream import follow
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


def merged(paths, idle_timeout):
    """Yield (kind, record) from several logs, ordered by timestamp."""
    gens = {}
    for kind, p in paths.items():
        if Path(p).exists():
            gens[kind] = follow(p, idle_timeout=idle_timeout)

    heap = []
    for kind, g in gens.items():
        try:
            rec = next(g)
            heapq.heappush(heap, (float(rec.get("ts", 0.0) or 0.0), kind, rec))
        except StopIteration:
            pass

    while heap:
        ts, kind, rec = heapq.heappop(heap)
        yield kind, rec
        try:
            nxt = next(gens[kind])
            heapq.heappush(heap, (float(nxt.get("ts", 0.0) or 0.0), kind, nxt))
        except StopIteration:
            pass


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

    def run(self, idle_timeout=5.0):
        paths = {"conn": self.logdir / "conn.log",
                 "dns": self.logdir / "dns.log",
                 "ssl": self.logdir / "ssl.log"}
        handlers = {"conn": self.on_conn, "dns": self.on_dns, "ssl": self.on_ssl}

        start = time.time()
        for kind, rec in merged(paths, idle_timeout):
            handlers[kind](rec)

        # Close only what genuinely went quiet; leave the rest open so the
        # dashboard can distinguish active incidents from resolved ones.
        self.agg.expire()
        for inc in self.agg.all_incidents():
            self.store.upsert_incident(inc)
        self.store.flush()

        elapsed = time.time() - start - idle_timeout
        return elapsed, start


def main():
    p = argparse.ArgumentParser(description="NetObs detection pipeline")
    p.add_argument("--logdir", required=True, help="directory of Zeek JSON logs")
    p.add_argument("--models", default="data/models")
    p.add_argument("--db", default="data/alerts.db")
    p.add_argument("--span", type=float, default=300.0)
    p.add_argument("--idle-timeout", type=float, default=5.0)
    p.add_argument("--keep-db", action="store_true")
    p.add_argument("--quiet", action="store_true")
    a = p.parse_args()

    pipe = Pipeline(a.logdir, a.models, a.db, span=a.span,
                    reset_db=not a.keep_db, quiet=a.quiet)
    print(f"reading {a.logdir}\n")
    elapsed, _ = pipe.run(idle_timeout=a.idle_timeout)

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
