#!/usr/bin/env python3
"""DNS threats: DGA domains (model) and DNS tunnelling (rule + statistics)."""
import sys
from collections import Counter, defaultdict, deque
from pathlib import Path

import joblib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from alerts.schema import Alert
from features.dns_features import NgramModel, domain_features, split_domain, shannon
from features.word_features import word_features

DGA_NAME = "dga_domain"
TUN_NAME = "dns_tunnel"

# Record types that carry more payload per answer; over-represented in tunnels.
HIGH_CAPACITY = {"TXT", "NULL", "CNAME", "MX", "SRV"}

# Name resolution that never involves a public domain.
LOCAL_TLDS = {"local", "localdomain", "lan", "home", "internal",
              "workgroup", "arpa", "invalid", "test", "onion"}
LOCAL_QTYPES = {"NIMLOC", "NB", "NBSTAT", "SRV-NB"}


def parent_domain(name):
    parts = [p for p in (name or "").lower().strip(".").split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else (parts[0] if parts else "")


def subdomain_part(name):
    parts = [p for p in (name or "").lower().strip(".").split(".") if p]
    return ".".join(parts[:-2]) if len(parts) > 2 else ""


class DNSDetector:
    def __init__(self, model_path, alert_at=0.85, observe_at=0.60,
                 span=120.0, cooldown=300.0,
                 tun_min_queries=40, tun_min_mean_len=25.0,
                 tun_min_entropy=3.0, tun_min_share=0.6):
        bundle = joblib.load(model_path)
        self.clf = bundle["clf"]
        self.bigrams = bundle["bigrams"]
        self.trigrams = bundle["trigrams"]

        self.alert_at = alert_at
        self.observe_at = observe_at
        self.cooldown = cooldown
        self.span = span

        self.tun_min_queries = tun_min_queries
        self.tun_min_mean_len = tun_min_mean_len
        self.tun_min_entropy = tun_min_entropy
        self.tun_min_share = tun_min_share

        self.seen_domain = {}
        self.alerted_domain = set()
        self.by_src = defaultdict(deque)
        self.tun_fired = {}
        self.now = 0.0
        self.scored = 0

    # ---------- DGA ----------

    def score_domain(self, name):
        label, _ = split_domain(name)
        if not label or len(label) < 5:
            return None
        base = domain_features(name, self.bigrams, self.trigrams)
        feats = base + word_features(label, base[12])
        self.scored += 1
        return float(self.clf.predict_proba([feats])[0][1])

    def check_domain(self, rec):
        name = (rec.get("query") or "").strip().lower()
        if not name or name.endswith(".arpa") or name.endswith(".local"):
            return None
        parts = [p for p in name.split(".") if p]
        if len(parts) < 2:
            return None          # single-label: NetBIOS/mDNS, not a domain
        if parts[-1] in LOCAL_TLDS or not parts[-1].isalpha():
            return None
        if (rec.get("qtype_name") or "") in LOCAL_QTYPES:
            return None

        parent = parent_domain(name)
        prob = self.seen_domain.get(parent)
        if prob is None:
            prob = self.score_domain(parent)
            if prob is None:
                return None
            self.seen_domain[parent] = prob

        if prob < self.observe_at:
            return None
        if parent in self.alerted_domain:
            return None
        self.alerted_domain.add(parent)

        label, _ = split_domain(parent)
        base = domain_features(parent, self.bigrams, self.trigrams)
        return Alert(
            ts=float(rec.get("ts", self.now)),
            threat_class=DGA_NAME,
            src=rec.get("id.orig_h", ""),
            dst=parent,
            confidence=prob,
            detector=f"{DGA_NAME}.lgbm",
            evidence={
                "domain": parent,
                "queried": name,
                "band": "alert" if prob >= self.alert_at else "observe",
                "label_length": len(label),
                "char_entropy": round(base[1], 2),
                "vowel_ratio": round(base[2], 3),
                "consonant_run": int(base[5]),
                "trigram_score": round(base[12], 2),
                "qtype": rec.get("qtype_name", ""),
            },
        )

    # ---------- tunnelling ----------

    def add_query(self, rec):
        ts = float(rec.get("ts", 0.0))
        if ts > self.now:
            self.now = ts
        src = rec.get("id.orig_h", "")
        if not src:
            return None, None
        q = self.by_src[src]
        q.append((ts, rec.get("query") or "", rec.get("qtype_name") or "",
                  int(rec.get("rejected", 0) or 0)))
        cutoff = self.now - self.span
        while q and q[0][0] < cutoff:
            q.popleft()
        return src, q

    def check_tunnel(self, src, queries):
        n = len(queries)
        if n < self.tun_min_queries:
            return None

        parents = Counter(parent_domain(q) for _, q, _, _ in queries)
        top_parent, top_count = parents.most_common(1)[0]
        share = top_count / n
        if share < self.tun_min_share:
            return None

        subs = [subdomain_part(q) for _, q, _, _ in queries
                if parent_domain(q) == top_parent]
        subs = [s for s in subs if s]
        if len(subs) < self.tun_min_queries // 2:
            return None

        mean_len = sum(len(s) for s in subs) / len(subs)
        if mean_len < self.tun_min_mean_len:
            return None

        ent = shannon("".join(subs[:200]))
        if ent < self.tun_min_entropy:
            return None

        unique_share = len(set(subs)) / len(subs)
        qtypes = Counter(t for _, _, t, _ in queries)
        hi_share = sum(c for t, c in qtypes.items() if t in HIGH_CAPACITY) / n

        last = self.tun_fired.get((src, top_parent))
        if last is not None and self.now - last < self.cooldown:
            return None
        self.tun_fired[(src, top_parent)] = self.now

        rate = n / self.span
        # Sustained volume to one domain matters more than raw speed: a slow
        # tunnel is evasive, not benign. Scale against the alerting floor.
        vol = min(1.0, n / (self.tun_min_queries * 2.0))
        length = min(1.0, mean_len / 45.0)
        confidence = (0.25 * vol + 0.30 * length + 0.20 * min(1.0, ent / 4.5)
                      + 0.15 * unique_share + 0.10 * hi_share)

        return Alert(
            ts=self.now, threat_class=TUN_NAME, src=src, dst=top_parent,
            confidence=confidence, detector=f"{TUN_NAME}.rule",
            evidence={
                "parent_domain": top_parent,
                "queries_in_window": n,
                "queries_per_sec": round(rate, 2),
                "domain_share": round(share, 3),
                "mean_subdomain_len": round(mean_len, 1),
                "subdomain_entropy": round(ent, 2),
                "unique_subdomain_ratio": round(unique_share, 3),
                "high_capacity_qtype_share": round(hi_share, 3),
                "qtypes": dict(qtypes.most_common(4)),
            },
        )
