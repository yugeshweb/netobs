#!/usr/bin/env python3
"""The one alert record every detector emits."""
import json, time
from dataclasses import dataclass, field, asdict

SEVERITY = ("info", "low", "medium", "high", "critical")


def severity_for(confidence):
    if confidence >= 0.90:
        return "critical"
    if confidence >= 0.75:
        return "high"
    if confidence >= 0.55:
        return "medium"
    if confidence >= 0.35:
        return "low"
    return "info"


@dataclass
class Alert:
    ts: float                      # traffic-clock time of detection
    threat_class: str              # e.g. "port_scan"
    src: str                       # offending source IP
    dst: str = ""                  # target, when there is a single one
    confidence: float = 0.0        # 0..1
    severity: str = ""
    detector: str = ""             # which component fired
    evidence: dict = field(default_factory=dict)
    flow_ids: list = field(default_factory=list)
    detected_at: float = field(default_factory=time.time)  # wall clock

    def __post_init__(self):
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        if not self.severity:
            self.severity = severity_for(self.confidence)

    def to_json(self):
        return json.dumps(asdict(self), separators=(",", ":"), default=str)

    def summary(self):
        return (f"[{self.severity:8s}] {self.threat_class:16s} "
                f"src={self.src:<16s} conf={self.confidence:.2f} "
                f"{self.evidence}")
