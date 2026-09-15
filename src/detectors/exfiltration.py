#!/usr/bin/env python3
"""Data exfiltration: sustained, lopsided outbound transfer from one source."""
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from alerts.schema import Alert

NAME = "exfiltration"

# Ports where heavy upload is expected and unremarkable.
UPLOAD_OK = {20, 21, 22, 873, 445, 139, 2049}


class ExfiltrationDetector:
    def __init__(self, min_ratio=3.0, min_bytes=5_000_000, min_flows=3,
                 cooldown=120.0, ignore_upload_ports=True):
        self.min_ratio = min_ratio
        self.min_bytes = min_bytes
        self.min_flows = min_flows
        self.cooldown = cooldown
        self.ignore_upload_ports = ignore_upload_ports
        self.last_fired = {}

    def check(self, src, flows, now):
        if len(flows) < self.min_flows:
            return None

        # Judge per destination: one big upload to one place is the signal,
        # not a source's overall traffic mix.
        by_dst = defaultdict(list)
        for f in flows:
            by_dst[f.dst].append(f)

        best = None
        for dst, fl in by_dst.items():
            if len(fl) < self.min_flows:
                continue
            out = sum(f.obytes for f in fl)
            inb = sum(f.rbytes for f in fl)
            if out < self.min_bytes:
                continue
            ratio = out / inb if inb > 0 else float(out)
            if ratio < self.min_ratio:
                continue
            if self.ignore_upload_ports and all(f.dport in UPLOAD_OK for f in fl):
                continue
            if best is None or out > best[1]:
                best = (dst, out, inb, ratio, fl)

        if best is None:
            return None

        dst, out, inb, ratio, fl = best
        key = (src, dst)
        last = self.last_fired.get(key)
        if last is not None and now - last < self.cooldown:
            return None
        self.last_fired[key] = now

        span = max(f.ts for f in fl) - min(f.ts for f in fl)
        rate = out / span if span > 0 else out

        volume = min(1.0, out / (self.min_bytes * 10))
        skew = min(1.0, ratio / (self.min_ratio * 5))
        support = min(1.0, len(fl) / (self.min_flows * 4))
        confidence = 0.4 * volume + 0.35 * skew + 0.25 * support

        ports = sorted({f.dport for f in fl})
        return Alert(
            ts=now, threat_class=NAME, src=src, dst=dst,
            confidence=confidence, detector=f"{NAME}.rule",
            evidence={
                "out_bytes": out,
                "in_bytes": inb,
                "out_in_ratio": round(ratio, 1),
                "flows": len(fl),
                "dest_ports": ports[:5],
                "transfer_seconds": round(span, 1),
                "bytes_per_sec": round(rate, 1),
            },
        )
