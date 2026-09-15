#!/usr/bin/env python3
"""Sliding time-window state, kept per source IP."""
from collections import defaultdict, deque


class FlowRecord:
    """One connection, reduced to what the detectors actually need."""
    __slots__ = ("ts", "src", "dst", "dport", "proto", "service",
                 "duration", "obytes", "rbytes", "opkts", "rpkts", "state")

    def __init__(self, rec):
        self.ts = float(rec.get("ts", 0.0))
        self.src = rec.get("id.orig_h", "")
        self.dst = rec.get("id.resp_h", "")
        self.dport = int(rec.get("id.resp_p", 0) or 0)
        self.proto = rec.get("proto", "")
        self.service = rec.get("service") or ""
        self.duration = float(rec.get("duration", 0.0) or 0.0)
        self.obytes = int(rec.get("orig_bytes", 0) or 0)
        self.rbytes = int(rec.get("resp_bytes", 0) or 0)
        self.opkts = int(rec.get("orig_pkts", 0) or 0)
        self.rpkts = int(rec.get("resp_pkts", 0) or 0)
        self.state = rec.get("conn_state", "")


class SlidingWindow:
    """Per-source history, trimmed to a fixed time span."""

    def __init__(self, span=60.0, max_idle=300.0):
        self.span = span
        self.max_idle = max_idle
        self.by_src = defaultdict(deque)
        self.last_seen = {}
        self.now = 0.0

    def add(self, flow):
        if flow.ts > self.now:
            self.now = flow.ts
        q = self.by_src[flow.src]
        q.append(flow)
        self.last_seen[flow.src] = flow.ts
        cutoff = self.now - self.span
        while q and q[0].ts < cutoff:
            q.popleft()
        return q

    def window_for(self, src):
        return self.by_src.get(src, deque())

    def evict_idle(self):
        """Forget sources that have gone quiet, so memory stays flat."""
        cutoff = self.now - self.max_idle
        dead = [s for s, t in self.last_seen.items() if t < cutoff]
        for s in dead:
            self.by_src.pop(s, None)
            self.last_seen.pop(s, None)
        return len(dead)

    def stats(self):
        return {
            "sources": len(self.by_src),
            "flows_held": sum(len(q) for q in self.by_src.values()),
            "clock": self.now,
        }
