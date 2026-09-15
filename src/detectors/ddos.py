#!/usr/bin/env python3
"""Volumetric, protocol and application-layer floods, tracked per target.

Fires on deviation from a per-target baseline rather than raw volume, so a
consistently busy service (DNS, a popular web server) is not an alert.
"""
import math, statistics, sys
from collections import Counter, defaultdict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from alerts.schema import Alert
from features.compute import entropy

NAME = "ddos"
INCOMPLETE = {"S0", "REJ", "RSTOS0", "SH", "S1"}


class DDoSDetector:
    def __init__(self, span=30.0, min_rate=100.0, min_incomplete=0.7,
                 min_sources=25, cooldown=60.0, max_pkts=10, min_small=0.7,
                 sample_every=3.0, keep_samples=20, min_samples=5, spike=5.0):
        self.span = span
        self.min_rate = min_rate
        self.min_incomplete = min_incomplete
        self.min_sources = min_sources
        self.cooldown = cooldown
        self.max_pkts = max_pkts
        self.min_small = min_small
        self.sample_every = sample_every
        self.keep_samples = keep_samples
        self.min_samples = min_samples
        self.spike = spike

        self.by_dst = defaultdict(deque)
        self.baseline = defaultdict(deque)
        self.last_sample = {}
        self.last_fired = {}
        self.now = 0.0

    def add(self, flow):
        if flow.ts > self.now:
            self.now = flow.ts
        key = (flow.dst, flow.dport)
        q = self.by_dst[key]
        q.append(flow)
        cutoff = self.now - self.span
        while q and q[0].ts < cutoff:
            q.popleft()

        last = self.last_sample.get(key)
        if last is None:
            self.last_sample[key] = self.now
        elif self.now - last >= self.sample_every:
            b = self.baseline[key]
            b.append(len(q) / self.span)
            while len(b) > self.keep_samples:
                b.popleft()
            self.last_sample[key] = self.now
        return key, q

    def _base(self, key):
        b = self.baseline[key]
        if len(b) < self.min_samples:
            return None
        return statistics.median(b)

    def check(self, key, flows):
        n = len(flows)
        if n < 50:
            return None
        rate = n / self.span
        if rate < self.min_rate:
            return None

        incomplete = sum(1 for f in flows if f.state in INCOMPLETE) / n
        small = sum(1 for f in flows if (f.opkts + f.rpkts) <= self.max_pkts) / n

        base = self._base(key)
        spike_ratio = rate / max(base, 1.0) if base is not None else None

        volumetric = incomplete >= self.min_incomplete
        app_layer = (small >= self.min_small
                     and spike_ratio is not None
                     and spike_ratio >= self.spike)
        if not (volumetric or app_layer):
            return None

        srcs = Counter(f.src for f in flows)
        if len(srcs) < self.min_sources:
            return None
        src_ent = entropy(srcs)
        max_ent = math.log2(len(srcs)) if len(srcs) > 1 else 1.0
        spread = src_ent / max_ent if max_ent > 0 else 0.0

        dst, dport = key
        last = self.last_fired.get(key)
        if last is not None and self.now - last < self.cooldown:
            return None
        self.last_fired[key] = self.now

        proto = Counter(f.proto for f in flows).most_common(1)[0][0]
        if proto == "udp":
            kind = "udp_flood"
        elif incomplete > 0.9:
            kind = "syn_flood"
        elif volumetric:
            kind = "connection_flood"
        else:
            kind = "application_flood"

        intensity = min(1.0, rate / (self.min_rate * 5))
        shape = incomplete if volumetric else small
        confidence = 0.4 * intensity + 0.35 * shape + 0.25 * spread

        return Alert(
            ts=self.now, threat_class=NAME, src=f"{len(srcs)} sources", dst=dst,
            confidence=confidence, detector=f"{NAME}.rule",
            evidence={
                "pattern": kind,
                "target_port": dport,
                "flows_per_sec": round(rate, 1),
                "baseline_per_sec": round(base, 1) if base is not None else None,
                "spike_ratio": round(spike_ratio, 1) if spike_ratio is not None else None,
                "flows_in_window": n,
                "distinct_sources": len(srcs),
                "source_entropy": round(src_ent, 2),
                "source_spread": round(spread, 3),
                "incomplete_ratio": round(incomplete, 3),
                "small_flow_ratio": round(small, 3),
                "protocol": proto,
            },
        )
