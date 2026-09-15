#!/usr/bin/env python3
"""SQLite persistence for alerts and incidents."""
import json
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            REAL NOT NULL,
  detected_at   REAL NOT NULL,
  threat_class  TEXT NOT NULL,
  src           TEXT,
  dst           TEXT,
  confidence    REAL,
  severity      TEXT,
  detector      TEXT,
  incident_key  TEXT,
  evidence      TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_key);

CREATE TABLE IF NOT EXISTS incidents (
  key             TEXT PRIMARY KEY,
  threat_class    TEXT NOT NULL,
  src             TEXT,
  dst             TEXT,
  first_seen      REAL,
  last_seen       REAL,
  count           INTEGER,
  peak_confidence REAL,
  severity        TEXT,
  detector        TEXT,
  status          TEXT,
  evidence        TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_last ON incidents(last_seen);
CREATE INDEX IF NOT EXISTS idx_incidents_sev ON incidents(severity);
"""


class AlertStore:
    def __init__(self, path, reset=False):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if reset and path.exists():
            path.unlink()
        self.db = sqlite3.connect(str(path))
        self.db.executescript(SCHEMA)
        self.db.commit()
        self._pending = 0

    def write_alert(self, alert, key):
        self.db.execute(
            "INSERT INTO alerts (ts, detected_at, threat_class, src, dst,"
            " confidence, severity, detector, incident_key, evidence)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (alert.ts, alert.detected_at, alert.threat_class, alert.src,
             alert.dst, alert.confidence, alert.severity, alert.detector,
             "|".join(str(p) for p in key), json.dumps(alert.evidence, default=str)))
        self._maybe_commit()

    def upsert_incident(self, inc):
        self.db.execute(
            "INSERT INTO incidents (key, threat_class, src, dst, first_seen,"
            " last_seen, count, peak_confidence, severity, detector, status, evidence)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(key) DO UPDATE SET"
            " last_seen=excluded.last_seen, count=excluded.count,"
            " peak_confidence=excluded.peak_confidence,"
            " severity=excluded.severity, status=excluded.status,"
            " evidence=excluded.evidence",
            ("|".join(str(p) for p in inc.key), inc.threat_class, inc.src,
             inc.dst, inc.first_seen, inc.last_seen, inc.count,
             inc.peak_confidence, inc.severity, inc.detector, inc.status,
             json.dumps(inc.peak_evidence, default=str)))
        self._maybe_commit()

    def _maybe_commit(self, force=False):
        self._pending += 1
        if force or self._pending >= 50:
            self.db.commit()
            self._pending = 0

    def flush(self):
        self.db.commit()
        self._pending = 0

    def counts(self):
        a = self.db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        i = self.db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        return {"alerts": a, "incidents": i}

    def close(self):
        self.flush()
        self.db.close()
