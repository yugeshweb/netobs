#!/usr/bin/env python3
"""NetObs dashboard API: reads the alert store, serves incidents and evidence.

Read-only over the database. The pipeline writes; this only queries.
"""
import asyncio
import json
import sqlite3
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from replay import REPLAY, list_captures

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "data" / "alerts.db"

app = FastAPI(title="NetObs")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def query(sql, args=()):
    # A replay starts by deleting and recreating the database, so for a
    # moment the file is missing or the tables are not there yet. Treat that
    # as "nothing to report" rather than letting it 500 or kill the socket.
    if not DB.exists():
        return []
    try:
        db = sqlite3.connect(str(DB))
    except sqlite3.Error:
        return []
    db.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in db.execute(sql, args).fetchall()]
    except sqlite3.Error:
        return []
    finally:
        db.close()


def _decode(rows, field="evidence"):
    for r in rows:
        if isinstance(r.get(field), str):
            try:
                r[field] = json.loads(r[field])
            except (ValueError, TypeError):
                r[field] = {}
    return rows


@app.get("/api/summary")
def summary():
    rows = query("SELECT severity, status, COUNT(*) n FROM incidents"
                 " GROUP BY severity, status")
    by_sev, open_n, closed_n = {}, 0, 0
    for r in rows:
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + r["n"]
        if r["status"] == "open":
            open_n += r["n"]
        else:
            closed_n += r["n"]

    classes = query("SELECT threat_class, COUNT(*) n FROM incidents"
                    " GROUP BY threat_class ORDER BY n DESC")
    hosts = query("SELECT src, COUNT(*) n, MAX(peak_confidence) c"
                  " FROM incidents WHERE src != '' GROUP BY src"
                  " ORDER BY n DESC LIMIT 5")
    totals = query("SELECT COUNT(*) n FROM alerts")

    return {
        "incidents_open": open_n,
        "incidents_closed": closed_n,
        "alerts_total": totals[0]["n"] if totals else 0,
        "by_severity": by_sev,
        "by_class": classes,
        "top_sources": hosts,
    }


@app.get("/api/incidents")
def incidents(status: str = "", severity: str = "",
              threat_class: str = "", limit: int = 200):
    sql = "SELECT * FROM incidents WHERE 1=1"
    args = []
    if status:
        sql += " AND status = ?"
        args.append(status)
    if severity:
        sql += " AND severity = ?"
        args.append(severity)
    if threat_class:
        sql += " AND threat_class = ?"
        args.append(threat_class)
    sql += " ORDER BY last_seen DESC LIMIT ?"
    args.append(limit)

    rows = _decode(query(sql, args))
    def rank(r):
        # Severity first, then how much evidence supports it: a three-hour
        # incident seen 178 times outranks a single observation of equal
        # severity. Recency breaks remaining ties.
        weight = r["count"] + (r["last_seen"] - r["first_seen"]) / 60.0
        return (SEVERITY_ORDER.get(r["severity"], 9),
                r["status"] != "open",
                -weight,
                -r["last_seen"])

    rows.sort(key=rank)
    return rows


@app.get("/api/incidents/{key:path}/alerts")
def incident_alerts(key: str, limit: int = 100):
    return _decode(query(
        "SELECT * FROM alerts WHERE incident_key = ?"
        " ORDER BY ts DESC LIMIT ?", (key, limit)))


@app.get("/api/alerts")
def alerts(limit: int = 100):
    return _decode(query(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)))


@app.websocket("/ws")
async def ws(sock: WebSocket):
    """Push incident changes as the pipeline writes them."""
    await sock.accept()
    last_alert_id = 0
    try:
        while True:
            rows = query("SELECT MAX(id) m FROM alerts")
            newest = (rows[0]["m"] or 0) if rows else 0
            if newest != last_alert_id:
                last_alert_id = newest
                await sock.send_json({
                    "type": "update",
                    "summary": summary(),
                    "incidents": incidents(limit=100),
                })
            await asyncio.sleep(1.0)
    except (WebSocketDisconnect, RuntimeError):
        return


@app.get("/api/captures")
def captures():
    return list_captures()


@app.get("/api/replay/status")
def replay_status():
    return REPLAY.status()


@app.post("/api/replay/start")
def replay_start(pcap: str, speed: float = 60.0):
    return REPLAY.start(pcap, speed)


@app.post("/api/replay/stop")
def replay_stop():
    REPLAY.stop()
    return REPLAY.status()


@app.get("/")
def index():
    f = Path(__file__).parent / "index.html"
    return FileResponse(str(f)) if f.exists() else {"status": "no ui yet"}
