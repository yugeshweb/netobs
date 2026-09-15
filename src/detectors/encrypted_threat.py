#!/usr/bin/env python3
"""Malware in encrypted sessions, from TLS metadata only.

Approach: JA4 client fingerprinting against a known-software allowlist, plus
structural red flags in the handshake and certificate. No payload is read and
nothing is decrypted.

Why not a classifier: a LightGBM model trained on 67k labelled TLS sessions
from 23 CTU captures, split by capture, reached ROC AUC 0.49 once lexical
features of the server name were removed. Malware that uses ordinary
certificates and legitimate-looking hosts is not separable from a browser on
handshake metadata alone. See docs/tls_dataset_notes.md.
"""
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from alerts.schema import Alert

NAME = "encrypted_malware"

# JA4 prefixes for client software confirmed on this network. Populate
# from a verified-clean observation period only: an entry seeded from
# unverified traffic will silently allowlist whatever produced it.
# Site-specific configuration, not a universal list.
KNOWN_CLIENTS = {
    "t13d3112h2": "curl/OpenSSL 3.x",
    "t13d1516h2": "Chrome/Edge (Chromium)",
    "t13d1517h2": "Firefox",
    "t13d1715h2": "Safari",
}

STD_TLS_PORTS = {443, 8443, 993, 995, 465, 587, 636, 989, 990, 5061}
KNOWN_CA_HINTS = ("let's encrypt", "digicert", "globalsign", "comodo",
                  "sectigo", "verisign", "thawte", "geotrust", "godaddy",
                  "amazon", "google trust", "entrust", "rapidssl",
                  "usertrust", "baltimore")


def _s(v):
    """Normalise a Zeek field to a string. JSON logs give native types,
    tab-separated logs give strings with '-' for unset."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "T" if v else "F"
    if not isinstance(v, str):
        return str(v)
    v = v.strip()
    return "" if v in ("-", "(empty)", "(unset)") else v


class EncryptedThreatDetector:
    """Scores TLS sessions on fingerprint familiarity and structural flags."""

    def __init__(self, min_score=0.45, observe_score=0.22, cooldown=300.0,
                 learn_window=200, rare_fp_threshold=3):
        self.min_score = min_score
        self.observe_score = observe_score
        self.cooldown = cooldown
        self.learn_window = learn_window
        self.rare_fp_threshold = rare_fp_threshold

        self.fp_counts = Counter()
        self.fp_dests = defaultdict(set)
        self.seen_sessions = 0
        self.last_fired = {}
        self.now = 0.0

    def observe(self, rec):
        """Track fingerprint frequency so rarity can be judged in context."""
        ja4 = _s(rec.get("ja4"))
        if ja4:
            self.fp_counts[ja4] += 1
            self.fp_dests[ja4].add(_s(rec.get("id.resp_h")))
        self.seen_sessions += 1

    def check(self, rec):
        ts = float(rec.get("ts", 0.0) or 0.0)
        if ts > self.now:
            self.now = ts

        src = _s(rec.get("id.orig_h"))
        dst = _s(rec.get("id.resp_h"))
        if not src:
            return None

        ja4 = _s(rec.get("ja4"))
        sni = _s(rec.get("server_name"))
        status = _s(rec.get("validation_status")).lower()
        subject = _s(rec.get("subject"))
        issuer = _s(rec.get("issuer"))
        try:
            port = int(_s(rec.get("id.resp_p")) or 0)
        except ValueError:
            port = 0

        flags = []
        score = 0.0

        # --- client identity ---
        client = None
        if ja4:
            prefix = ja4.split("_")[0]
            client = KNOWN_CLIENTS.get(prefix)
            if client is None:
                seen = self.fp_counts.get(ja4, 0)
                if seen <= self.rare_fp_threshold and self.seen_sessions > self.learn_window:
                    flags.append("unrecognised_rare_client")
                    score += 0.40
                else:
                    flags.append("unrecognised_client")
                    score += 0.25
        else:
            flags.append("no_fingerprint")
            score += 0.10

        # --- structural red flags ---
        if not sni:
            flags.append("no_sni")
            score += 0.25

        if "self signed" in status:
            flags.append("self_signed_cert")
            score += 0.30
        elif status and status != "ok":
            flags.append(f"cert_{status.replace(' ', '_')[:28]}")
            score += 0.15

        if subject and subject == issuer:
            flags.append("subject_equals_issuer")
            score += 0.15

        if issuer and not any(h in issuer.lower() for h in KNOWN_CA_HINTS):
            if "self signed" not in status:
                flags.append("unknown_issuer")
                score += 0.10

        if port and port not in STD_TLS_PORTS:
            flags.append(f"tls_on_port_{port}")
            score += 0.20

        if score < self.observe_score:
            return None
        band = "alert" if score >= self.min_score else "observe"

        key = (src, dst, ja4 or "none")
        last = self.last_fired.get(key)
        if last is not None and self.now - last < self.cooldown:
            return None
        self.last_fired[key] = self.now

        return Alert(
            ts=ts or self.now, threat_class=NAME, src=src, dst=dst,
            confidence=min(score, 1.0), detector=f"{NAME}.rule",
            evidence={
                "band": band,
                "flags": flags,
                "ja4": ja4 or None,
                "identified_client": client,
                "fingerprint_seen_count": self.fp_counts.get(ja4, 0) if ja4 else None,
                "server_name": sni or None,
                "dest_port": port,
                "cert_status": status or None,
                "cert_issuer": issuer[:80] or None,
            },
        )
