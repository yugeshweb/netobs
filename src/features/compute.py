#!/usr/bin/env python3
"""Turn a source's recent window into the numbers detectors consume."""
import math
from collections import Counter, defaultdict

FAILED_STATES = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"}


def entropy(counts):
    """Shannon entropy over a Counter, in bits."""
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts.values():
        p = c / total
        h -= p * math.log2(p)
    return h


def cv(values):
    """Coefficient of variation: spread relative to the mean."""
    if len(values) < 2:
        return None
    mean = sum(values) / len(values)
    if mean <= 0:
        return None
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(var) / mean


def beacon_score(flows):
    """Lowest gap-variation across destinations this source repeats to."""
    by_dst = defaultdict(list)
    for f in flows:
        by_dst[(f.dst, f.dport)].append(f.ts)

    best = None
    for key, times in by_dst.items():
        if len(times) < 4:
            continue
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
        if len(gaps) < 3:
            continue
        c = cv(gaps)
        if c is None:
            continue
        if best is None or c < best[0]:
            best = (c, key, len(times), sum(gaps) / len(gaps))
    if best is None:
        return {}
    return {
        "beacon_cv": best[0],
        "beacon_dst": f"{best[1][0]}:{best[1][1]}",
        "beacon_hits": best[2],
        "beacon_period": best[3],
    }


def features_for(src, flows, span):
    """Build the full feature row for one source IP."""
    n = len(flows)
    if n == 0:
        return None

    dports = Counter(f.dport for f in flows)
    dsts = Counter(f.dst for f in flows)
    obytes = sum(f.obytes for f in flows)
    rbytes = sum(f.rbytes for f in flows)
    failed = sum(1 for f in flows if f.state in FAILED_STATES)

    row = {
        "src": src,
        "ts": max(f.ts for f in flows),
        "n_flows": n,
        "flow_rate": n / span,
        "n_dst_ports": len(dports),
        "n_dst_hosts": len(dsts),
        "port_entropy": entropy(dports),
        "dst_entropy": entropy(dsts),
        "top_dst_share": dsts.most_common(1)[0][1] / n,
        "failed_ratio": failed / n,
        "out_bytes": obytes,
        "in_bytes": rbytes,
        "out_in_ratio": obytes / rbytes if rbytes > 0 else (obytes if obytes else 0.0),
        "mean_duration": sum(f.duration for f in flows) / n,
        "mean_out_pkts": sum(f.opkts for f in flows) / n,
        "small_flow_ratio": sum(1 for f in flows if f.opkts <= 2) / n,
    }
    row.update(beacon_score(flows))
    return row
