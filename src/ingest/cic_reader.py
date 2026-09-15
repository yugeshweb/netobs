#!/usr/bin/env python3
"""Adapt CIC-IDS2017 CSV rows into the FlowRecord shape the detectors expect."""
import csv, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from features.window import FlowRecord


def _num(v, cast=float, default=0):
    try:
        x = cast(float(str(v).strip()))
        return x if x == x and abs(x) != float("inf") else default
    except (ValueError, TypeError):
        return default


def read_cic(path, limit=None, synth_sources=200):
    """Yield (FlowRecord, label) pairs from a CIC MachineLearning CSV."""
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        rdr = csv.reader(f)
        header = [h.strip() for h in next(rdr)]
        idx = {h: i for i, h in enumerate(header)}

        def col(row, name, cast=float, default=0):
            i = idx.get(name)
            return _num(row[i], cast, default) if i is not None and i < len(row) else default

        clock = 0.0
        for n, row in enumerate(rdr):
            if not row or len(row) < 10:
                continue
            label = row[-1].strip()
            dur_us = col(row, "Flow Duration")
            dur = max(dur_us / 1e6, 0.0)
            fwd_pkts = col(row, "Total Fwd Packets", int)
            bwd_pkts = col(row, "Total Backward Packets", int)
            fwd_bytes = col(row, "Total Length of Fwd Packets", int)
            bwd_bytes = col(row, "Total Length of Bwd Packets", int)
            dport = col(row, "Destination Port", int)

            clock += 0.001
            attack = label.upper() != "BENIGN"
            src = f"10.{(n // 254) % 254}.{n % 254}.{(n * 7) % 254}" if attack \
                  else f"192.168.{(n % synth_sources) // 254}.{(n % synth_sources) % 254}"

            state = "SF"
            if bwd_pkts == 0 and fwd_pkts > 0:
                state = "S0"
            elif bwd_bytes == 0 and bwd_pkts <= 1:
                state = "REJ"

            yield FlowRecord({
                "ts": clock,
                "id.orig_h": src,
                "id.resp_h": "192.168.10.50",
                "id.resp_p": dport,
                "proto": "tcp",
                "duration": dur,
                "orig_bytes": fwd_bytes,
                "resp_bytes": bwd_bytes,
                "orig_pkts": fwd_pkts,
                "resp_pkts": bwd_pkts,
                "conn_state": state,
            }), label

            if limit and n + 1 >= limit:
                return
