#!/usr/bin/env python3
"""Collapse repeated alerts about the same situation into incidents.

An alert is one observation. An incident is an ongoing situation, keyed by
threat class and the parties involved. Detectors fire repeatedly while a
threat persists; the dashboard needs one row per situation, not per firing.
"""
import time
from dataclasses import dataclass, field, asdict

from .schema import severity_for


def incident_key(alert):
    """What counts as 'the same situation'.

    Threat class plus source, and destination where a specific target is
    meaningful. DDoS is keyed on the target because the sources are many and
    spoofed; everything else is keyed on the source that is misbehaving.
    """
    if alert.threat_class == "ddos":
        return (alert.threat_class, alert.dst or "", str(
            alert.evidence.get("target_port", "")))
    if alert.threat_class == "encrypted_malware":
        # Key on the client fingerprint, not the destination: one unknown
        # client contacting many hosts is a single finding, not many.
        fp = alert.evidence.get("ja4") or "no-fingerprint"
        return (alert.threat_class, alert.src, fp)
    if alert.threat_class in ("exfiltration", "c2_beacon", "dns_tunnel"):
        return (alert.threat_class, alert.src, alert.dst or "")
    return (alert.threat_class, alert.src, "")


@dataclass
class Incident:
    key: tuple
    threat_class: str
    src: str
    dst: str
    first_seen: float                 # traffic clock
    last_seen: float
    count: int = 1
    peak_confidence: float = 0.0
    last_confidence: float = 0.0
    severity: str = "info"
    detector: str = ""
    evidence: dict = field(default_factory=dict)
    peak_evidence: dict = field(default_factory=dict)
    bands: dict = field(default_factory=dict)
    opened_at: float = field(default_factory=time.time)
    status: str = "open"

    def to_dict(self):
        d = asdict(self)
        d["key"] = "|".join(str(p) for p in self.key)
        d["duration"] = round(self.last_seen - self.first_seen, 1)
        return d

    def summary(self):
        dur = self.last_seen - self.first_seen
        where = f"{self.src} -> {self.dst}" if self.dst else self.src
        return (f"[{self.severity:8s}] {self.threat_class:18s} {where:38s} "
                f"x{self.count:<5d} peak={self.peak_confidence:.2f} "
                f"{dur:.0f}s")


class IncidentAggregator:
    """Folds alerts into incidents and reports what changed."""

    def __init__(self, idle_close=600.0, update_every=30.0,
                 confidence_jump=0.15):
        self.idle_close = idle_close
        self.update_every = update_every
        self.confidence_jump = confidence_jump
        self.open = {}
        self.closed = []
        self._by_key = {}
        self._last_emit = {}
        self.now = 0.0

    def add(self, alert):
        """Returns (event, incident) where event is 'new', 'update' or None.

        None means the incident exists and nothing worth reporting changed —
        that is the case that used to produce 164 duplicate rows.
        """
        if alert.ts > self.now:
            self.now = alert.ts

        key = incident_key(alert)
        inc = self.open.get(key)

        if inc is None:
            prior = self._by_key.get(key)
            if prior is not None and prior.status == "closed":
                # Same situation resuming after a quiet period: reopen and
                # keep the history rather than restarting the count.
                prior.status = "open"
                prior.last_seen = alert.ts
                prior.count += 1
                dom = alert.evidence.get("domain")
                if dom:
                    seen = prior.peak_evidence.setdefault("domains", [])
                    if dom not in seen:
                        seen.append(dom)
                self.open[key] = prior
                if prior in self.closed:
                    self.closed.remove(prior)
                self._last_emit[key] = alert.ts
                return "update", prior
            inc = Incident(
                key=key, threat_class=alert.threat_class,
                src=alert.src, dst=alert.dst,
                first_seen=alert.ts, last_seen=alert.ts,
                peak_confidence=alert.confidence,
                last_confidence=alert.confidence,
                severity=alert.severity, detector=alert.detector,
                evidence=dict(alert.evidence),
                peak_evidence=dict(alert.evidence),
            )
            band = alert.evidence.get("band")
            if band:
                inc.bands[band] = 1
            dom = alert.evidence.get("domain")
            if dom:
                inc.peak_evidence["domains"] = [dom]
            self.open[key] = inc
            self._by_key[key] = inc
            self._last_emit[key] = alert.ts
            return "new", inc

        inc.count += 1
        inc.last_seen = alert.ts
        dom = alert.evidence.get("domain")
        if dom:
            seen = inc.peak_evidence.setdefault("domains", [])
            if dom not in seen:
                seen.append(dom)
        inc.last_confidence = alert.confidence
        inc.evidence = dict(alert.evidence)
        band = alert.evidence.get("band")
        if band:
            inc.bands[band] = inc.bands.get(band, 0) + 1

        jumped = alert.confidence >= inc.peak_confidence + self.confidence_jump
        if alert.confidence > inc.peak_confidence:
            inc.peak_confidence = alert.confidence
            inc.peak_evidence = dict(alert.evidence)
            inc.severity = severity_for(inc.peak_confidence)

        due = alert.ts - self._last_emit.get(key, 0.0) >= self.update_every
        if jumped or due:
            self._last_emit[key] = alert.ts
            return "update", inc
        return None, inc

    def expire(self, now=None):
        """Close incidents that have gone quiet. Returns those closed."""
        t = self.now if now is None else now
        dead = [k for k, i in self.open.items() if t - i.last_seen > self.idle_close]
        out = []
        for k in dead:
            inc = self.open.pop(k)
            inc.status = "closed"
            self.closed.append(inc)
            self._last_emit.pop(k, None)
            out.append(inc)
        return out

    def all_incidents(self):
        return list(self.open.values()) + self.closed

    def stats(self):
        return {"open": len(self.open), "closed": len(self.closed),
                "total": len(self.open) + len(self.closed)}
