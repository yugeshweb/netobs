#!/usr/bin/env python3
"""Replay a capture at a controlled rate so detections arrive progressively.

Zeek converts the pcap once; a feeder then copies records into a live log
directory pacing them against their own timestamps, scaled by `speed`. The
pipeline follows that directory exactly as it would follow a live sensor, and
is started from here so one control drives the whole demo.
"""
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAPTURES = ROOT / "data" / "raw"
STAGE = ROOT / "data" / "replay" / "staged"
LIVE = ROOT / "data" / "replay" / "live"
PIPELINE_LOG = ROOT / "data" / "replay" / "pipeline.log"
KINDS = ("conn.log", "dns.log", "ssl.log")

# Two facts about the pipeline constrain the hand-off.
#
# merged() only opens logs that exist when it starts, and then follows each
# one with its own generator. So every log the capture will produce has to
# exist before the pipeline is spawned -- but a log that stays empty forever
# is worse than absent, because merged() blocks on it while priming the heap
# and nothing is processed until it times out. Create exactly the logs that
# have records, no more.
#
# And follow() gives up after idle_timeout seconds without a new line. That
# is measured per log, so the timeout has to outlast the longest quiet
# stretch any single log will see -- including the wait for its first record.
# ssl.log in the Neris capture has a 2390s internal gap, which at 60x is 40s
# of silence; too short a timeout there drops every later TLS session without
# saying so.
MIN_IDLE = 20.0
MAX_IDLE = 600.0
IDLE_MARGIN = 15.0


def list_captures():
    out = []
    for p in sorted(CAPTURES.rglob("*.pcap")):
        out.append({
            "path": str(p.relative_to(ROOT)),
            "name": p.name,
            "size_mb": round(p.stat().st_size / 1e6, 1),
        })
    return out


class Replay:
    """Runs one replay at a time, with its own pipeline process."""

    def __init__(self):
        self.thread = None
        self.zeek = None
        self.proc = None
        self._log = None
        self.stop_flag = threading.Event()
        self.state = {"running": False, "capture": None, "speed": 1.0,
                      "records": 0, "total": 0, "phase": "idle",
                      "pipeline": None, "idle_timeout": None}

    def status(self):
        return dict(self.state)

    def stop(self):
        self.stop_flag.set()
        self._kill(self.zeek)
        self._kill(self.proc)
        if self.thread:
            self.thread.join(timeout=10)
        self.state["running"] = False
        self.state["phase"] = "stopped"

    def start(self, pcap, speed=60.0):
        if self.state["running"]:
            return {"error": "a replay is already running"}
        pcap = (ROOT / pcap).resolve()
        if not pcap.exists():
            return {"error": f"no such capture: {pcap}"}

        self.stop_flag.clear()
        self.state.update({"running": True, "capture": pcap.name,
                           "speed": speed, "records": 0, "total": 0,
                           "phase": "converting", "pipeline": None,
                           "idle_timeout": None})
        self.thread = threading.Thread(target=self._run, args=(pcap, speed),
                                       daemon=True)
        self.thread.start()
        return {"ok": True, "capture": pcap.name, "speed": speed}

    # -- subprocess helpers ------------------------------------------------

    @staticmethod
    def _kill(p):
        if p is None or p.poll() is not None:
            return
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()

    def _start_pipeline(self, idle_timeout):
        """Spawn the detection pipeline against the live log directory."""
        PIPELINE_LOG.parent.mkdir(parents=True, exist_ok=True)
        self._log = PIPELINE_LOG.open("w")
        self.proc = subprocess.Popen(
            [sys.executable, "-u", "src/pipeline.py",
             "--logdir", str(LIVE.relative_to(ROOT)),
             "--quiet", "--idle-timeout", f"{idle_timeout:.0f}"],
            cwd=str(ROOT), stdout=self._log, stderr=subprocess.STDOUT)
        self.state["pipeline"] = "running"

    def _await_pipeline(self, timeout):
        """Wait for the pipeline to idle out so it flushes its final state."""
        if self.proc is None:
            return
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return
            if self.stop_flag.is_set():
                break
            time.sleep(0.25)
        self._kill(self.proc)

    # -- the replay itself -------------------------------------------------

    def _run(self, pcap, speed):
        try:
            STAGE.mkdir(parents=True, exist_ok=True)
            LIVE.mkdir(parents=True, exist_ok=True)
            for f in list(STAGE.glob("*.log")) + list(LIVE.glob("*.log")):
                f.unlink()

            # Same invocation as scripts/run_zeek.sh: -C because WSL checksum
            # offloading makes captures look corrupt, JSON output, and the
            # JA4 package path. Popen rather than run() so stop() can cut a
            # long conversion short.
            self.zeek = subprocess.Popen(
                ["zeek", "-C", "-r", str(pcap), "LogAscii::use_json=T",
                 str(Path.home() / ".zkg" / "script_dir" / "packages")],
                cwd=str(STAGE),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            rc = self.zeek.wait()
            self.zeek = None
            if self.stop_flag.is_set():
                return
            if rc != 0:
                self.state["phase"] = "zeek failed"
                return

            # Zeek appends a record when the connection closes, so a log is
            # in write order, not timestamp order. conn.log here steps
            # backwards 6431 times, once by 11653s. Pacing on `ts` would
            # reorder the file into something no live sensor could produce,
            # and something different from the staged file every measured
            # number in docs/ was taken from. So keep each log's own order
            # and pace on when Zeek wrote the line -- ts + duration, forced
            # non-decreasing. The line itself is copied verbatim, so the
            # traffic clock the detectors read is untouched.
            records = []
            stamps = {}
            for kind in KINDS:
                f = STAGE / kind
                if not f.exists():
                    continue
                emit = None
                for line in f.open():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        rec = json.loads(line)
                        wrote = (float(rec.get("ts", 0.0))
                                 + float(rec.get("duration") or 0.0))
                    except (ValueError, TypeError, AttributeError):
                        continue
                    emit = wrote if emit is None else max(emit, wrote)
                    records.append((emit, kind, line))
                    stamps.setdefault(kind, []).append(emit)
            # Stable sort on the emit time alone. Each log's records were
            # appended in file order and their emit times never decrease, so
            # stability is what keeps that order intact.
            records.sort(key=lambda r: r[0])

            self.state["total"] = len(records)
            if not records:
                self.state["phase"] = "empty"
                return

            spd = max(speed, 0.001)
            t0 = records[0][0]
            kinds = [k for k in KINDS if stamps.get(k)]

            # The longest any one follow() will sit without a line: the wait
            # for that log's first record, or its widest internal gap.
            worst = 0.0
            for k in kinds:
                ts = sorted(stamps[k])
                waits = [ts[0] - t0] + [b - a for a, b in zip(ts, ts[1:])]
                worst = max(worst, max(waits))
            idle_timeout = min(MAX_IDLE,
                               max(MIN_IDLE, worst / spd + IDLE_MARGIN))
            self.state["idle_timeout"] = round(idle_timeout, 1)

            # Creating them here is what lets the pipeline find every log when
            # it starts a moment from now. follow() reads from the beginning,
            # so nothing written during its startup is missed.
            handles = {k: (LIVE / k).open("a") for k in kinds}
            self._start_pipeline(idle_timeout)

            self.state["phase"] = "replaying"
            wall0 = time.time()

            for i, (ts, kind, line) in enumerate(records):
                if self.stop_flag.is_set():
                    break
                # Wait out the whole gap, in short hops so stop stays
                # responsive. Sleeping once and writing anyway would clip
                # every gap longer than the hop and finish early.
                while not self.stop_flag.is_set():
                    behind = (ts - t0) / spd - (time.time() - wall0)
                    if behind <= 0:
                        break
                    time.sleep(min(behind, 0.25))
                handles[kind].write(line + "\n")
                handles[kind].flush()
                self.state["records"] = i + 1

            for h in handles.values():
                h.close()
            if self.stop_flag.is_set():
                return

            # Let the pipeline idle out by itself rather than killing it: the
            # final incident states are only written after merged() returns.
            # merged() waits out idle_timeout on each log in turn before it
            # returns, so the tail is per-log, not shared.
            self.state["phase"] = "draining"
            self._await_pipeline(len(kinds) * idle_timeout + 30.0)
            self.state["phase"] = "finished"
        except subprocess.SubprocessError as e:
            self.state["phase"] = f"error: {e}"
        except OSError as e:
            self.state["phase"] = f"error: {e}"
        finally:
            self._kill(self.zeek)
            self.zeek = None
            if self.stop_flag.is_set():
                self._kill(self.proc)
            if self.proc is not None:
                rc = self.proc.poll()
                self.state["pipeline"] = ("running" if rc is None
                                          else f"exited {rc}")
            if self._log is not None:
                self._log.close()
                self._log = None
            self.state["running"] = False


REPLAY = Replay()
