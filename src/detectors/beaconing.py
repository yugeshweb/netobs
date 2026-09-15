#!/usr/bin/env python3
"""Botnet C2 beaconing: periodic contact to a small set of destinations."""
import statistics
import sys
from collections import defaultdict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from alerts.schema import Alert

NAME = "c2_beacon"

# Ports whose regular contact is routine infrastructure, not C2.
INFRA_PORTS = {123, 67, 68, 546, 547, 5353, 1900, 137, 138}


class BeaconDetector:
    """Tracks per (src, dst, port) contact timing over a long window."""

    def __init__(self, span=1800.0, min_hits=8, max_cv=0.35,
                 min_period=1.0, max_period=900.0, cooldown=600.0,
                 max_mean_bytes=8192, max_mean_in=4096, keep=200):
        self.span = span
        self.min_hits = min_hits
        self.max_cv = max_cv
        self.min_period = min_period
        self.max_period = max_period
        self.cooldown = cooldown
        self.max_mean_bytes = max_mean_bytes
        self.max_mean_in = max_mean_in
        self.keep = keep

        self.tracks = defaultdict(lambda: deque(maxlen=keep))
        self.last_fired = {}
        self.now = 0.0

    def add(self, flow):
        if flow.ts > self.now:
            self.now = flow.ts
        if flow.dport in INFRA_PORTS:
            return None
        key = (flow.src, flow.dst, flow.dport)
        t = self.tracks[key]
        t.append((flow.ts, flow.obytes, flow.rbytes, flow.duration))
        cutoff = self.now - self.span
        while t and t[0][0] < cutoff:
            t.popleft()
        return key

    def check(self, key):
        t = self.tracks.get(key)
        if not t or len(t) < self.min_hits:
            return None

        times = [x[0] for x in t]
        gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0.05]
        if len(gaps) < self.min_hits - 1:
            return None

        period = statistics.median(gaps)
        if not (self.min_period <= period <= self.max_period):
            return None

        mean_gap = sum(gaps) / len(gaps)
        if mean_gap <= 0:
            return None
        sd = statistics.pstdev(gaps)
        cv = sd / mean_gap
        if cv > self.max_cv:
            return None

        obytes = [x[1] for x in t]
        rbytes = [x[2] for x in t]
        mean_out = sum(obytes) / len(obytes)
        if mean_out > self.max_mean_bytes:
            return None                      # bulk transfer, not a check-in

        mean_in = sum(rbytes) / len(rbytes)
        # A C2 check-in receives a short, consistent reply. A benign beacon
        # fetching content pulls back far more, and varies with the content.
        if mean_in > self.max_mean_in:
            return None
        size_cv = (statistics.pstdev(obytes) / mean_out) if mean_out > 0 else 1.0
        in_cv = (statistics.pstdev(rbytes) / mean_in) if mean_in > 0 else 1.0
        duration = times[-1] - times[0]

        src, dst, dport = key
        last = self.last_fired.get(key)
        if last is not None and self.now - last < self.cooldown:
            return None
        self.last_fired[key] = self.now

        # Perfect regularity is usually infrastructure; deliberate jitter in
        # the 0.05-0.25 band is the malware signature.
        if cv < 0.02:
            timing = 0.45
            profile = "machine_exact"
        elif cv <= 0.25:
            timing = 1.0
            profile = "jittered_beacon"
        else:
            timing = 0.7
            profile = "loose_beacon"

        persistence = min(1.0, duration / (self.span / 2))
        consistency = max(0.0, 1.0 - min((size_cv + in_cv) / 2, 1.0))
        support = min(1.0, len(t) / (self.min_hits * 3))

        confidence = (0.35 * timing + 0.25 * persistence
                      + 0.20 * consistency + 0.20 * support)

        return Alert(
            ts=self.now, threat_class=NAME, src=src, dst=dst,
            confidence=confidence, detector=f"{NAME}.rule",
            evidence={
                "profile": profile,
                "dest_port": dport,
                "contacts": len(t),
                "period_sec": round(period, 1),
                "gap_cv": round(cv, 3),
                "observed_sec": round(duration, 1),
                "mean_out_bytes": round(mean_out, 1),
                "mean_in_bytes": round(mean_in, 1),
                "out_size_cv": round(size_cv, 3),
                "in_size_cv": round(in_cv, 3),
            },
        )
