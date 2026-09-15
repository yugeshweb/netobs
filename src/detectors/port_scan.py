#!/usr/bin/env python3
"""Reconnaissance: one source fanning out across ports or hosts."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from alerts.schema import Alert

NAME = "port_scan"


class PortScanDetector:
    def __init__(self, min_flows=20, min_ports=30, min_hosts=15,
                 min_failed=0.5, min_small=0.6, cooldown=60.0):
        self.min_flows = min_flows
        self.min_ports = min_ports
        self.min_hosts = min_hosts
        self.min_failed = min_failed
        self.min_small = min_small
        self.cooldown = cooldown
        self.last_fired = {}

    def check(self, row):
        if row["n_flows"] < self.min_flows:
            return None
        if row["failed_ratio"] < self.min_failed:
            return None
        if row["small_flow_ratio"] < self.min_small:
            return None

        ports, hosts = row["n_dst_ports"], row["n_dst_hosts"]
        if ports >= self.min_ports and hosts >= self.min_hosts:
            kind, scale = "hybrid_scan", max(ports / self.min_ports,
                                             hosts / self.min_hosts)
        elif hosts >= self.min_hosts:
            kind, scale = "horizontal_scan", hosts / self.min_hosts
        elif ports >= self.min_ports:
            kind, scale = "vertical_scan", ports / self.min_ports
        else:
            return None

        last = self.last_fired.get(row["src"])
        if last is not None and row["ts"] - last < self.cooldown:
            return None
        self.last_fired[row["src"]] = row["ts"]

        breadth = min(1.0, 0.35 + 0.25 * min(scale, 4.0))
        support = min(1.0, row["n_flows"] / (self.min_flows * 5))
        quality = (row["failed_ratio"] + row["small_flow_ratio"]) / 2
        confidence = 0.5 * breadth + 0.25 * support + 0.25 * quality

        return Alert(
            ts=row["ts"], threat_class=NAME, src=row["src"],
            confidence=confidence, detector=f"{NAME}.rule",
            evidence={
                "pattern": kind,
                "distinct_ports": ports,
                "distinct_hosts": hosts,
                "flows_in_window": row["n_flows"],
                "failed_ratio": round(row["failed_ratio"], 3),
                "small_flow_ratio": round(row["small_flow_ratio"], 3),
                "port_entropy": round(row["port_entropy"], 2),
            },
        )
