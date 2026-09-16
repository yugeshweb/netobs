# NetObs

Passive detection of cyber threats in one-directional IP traffic.

Smart India Hackathon 2026, problem statement from NTRO. A critical-
infrastructure operator mirrors gateway traffic into an isolated monitoring
enclave through a one-way link (a data diode). The enclave sees everything
crossing the link but has no path back — it cannot probe, cannot complete a
handshake, cannot push a mitigation. NetObs is the intelligence layer for that
enclave: it ingests the passive stream, detects and scores threats in near real
time, and presents labelled alerts with supporting evidence on a dashboard.

## What it detects

Six threat classes, from passively observed flow and metadata only:

- **Volumetric / protocol DDoS** — SYN floods and spoofed-source floods, by
  rate and source-IP entropy.
- **C2 beaconing** — flows repeating on a regular period toward a few
  destinations.
- **DGA domains and DNS tunnelling** — algorithmically generated query names,
  and payload smuggled in subdomain labels.
- **Malware in encrypted sessions** — from TLS metadata alone (JA4
  fingerprints, handshake structure), with no payload decryption.
- **Reconnaissance / port scanning** — fan-out from one source across many
  ports or hosts.
- **Data exfiltration** — asymmetric outbound volume to a single destination.

Each detection is a rule where the behaviour is definitional and a model where
it is genuinely statistical — a port scan is a rule that can state exactly which
thresholds it crossed; a DGA domain is a LightGBM classifier. See
[docs/models.md](docs/models.md) for the full per-detector account.

## The constraints it respects

These come from the problem statement and are non-negotiable:

- **Read-only ingest, by construction.** The only input is a set of log files
  another process appends to. There is no code path that can contact, probe, or
  block anything on the network.
- **No payload decryption.** Encrypted sessions are judged on metadata only.
- **Streaming, not batch.** Records are processed incrementally and alerts are
  raised with bounded latency (p99 0.68 s — [docs/latency.md](docs/latency.md)),
  not as an end-of-run report.
- **A stated throughput target** (~10,000 records/s, with its honest limits —
  [docs/throughput.md](docs/throughput.md)).
- **A standardised alert schema** — timestamp, flow identifier, threat class,
  confidence, and supporting evidence, kept as a full audit trail.

## How it works

**Zeek is the sensor, Python is the brain.** Zeek parses protocols and writes
structured JSON logs; the pipeline follows those logs line by line as they are
written, exactly like `tail -f` feeding a program. That is what makes it
streaming, and what makes it read-only — the pipeline only ever reads a file.

```
pcap / live iface → Zeek → conn.log / dns.log / ssl.log (JSON, appended live)
                              → pipeline: merge by traffic clock → six detectors
                              → alerts → incidents → SQLite → dashboard
```

All time-based state runs on the **traffic clock** (the newest timestamp in the
data), never the wall clock, so a 2011 capture replays and scores identically to
live traffic.

## Quickstart

The repository ships with a trained DGA model and an `alerts.db` already
populated from the CTU-13 Neris capture (225 alerts, 14 incidents), so the
dashboard shows real detections with no capture or Zeek setup required.

```bash
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt

cd dashboard && uvicorn api:app --port 8000    # do not use --reload
```

Open <http://localhost:8000>. You are looking at the fourteen incidents found in the
Neris botnet capture — a horizontal port scan, C2 beaconing, DGA domains, and
suspicious TLS — each with its confidence, severity, and the evidence behind it.

## Running it on your own traffic

Turning a capture into logs needs Zeek and the JA4 plugin (system installs, not
pip):

- **Zeek 8.2.2** — <https://zeek.org>. Put it on `PATH`.
- **JA4 plugin** — `zkg install zeek/foxio/ja4`. Without it the `ja4` field is
  absent and the encrypted-session detector has nothing to fingerprint.

Then, always through the wrapper (it applies `-C` for WSL checksum offloading,
JSON output, and the JA4 package path — all easy to forget):

```bash
./scripts/run_zeek.sh path/to/capture.pcap data/raw/mycap/zeeklogs
python3 src/pipeline.py --logdir data/raw/mycap/zeeklogs
```

**Paced replay for a live demo.** The dashboard header has a replay control:
pick a capture, pick a speed (1/10/60/300×), press start. Zeek converts the
pcap, a feeder paces records into a live directory, and the pipeline follows it
as it would a real sensor, so incidents appear progressively while you watch.

**Generate lab traffic** if you have no capture to hand:

```bash
./scripts/make_ddos.sh          # SYN flood + benign control  (needs sudo)
./scripts/make_exfil.sh         # asymmetric exfiltration
./scripts/make_dns_tunnel.sh    # DNS tunnel
./scripts/make_benign_beacons.sh
```

## Documentation

- [docs/models.md](docs/models.md) — models, features, and validation, per
  detector. Start here.
- [docs/dga_operating_point.md](docs/dga_operating_point.md) — DGA threshold
  selection and per-family recall.
- [docs/beacon_validation.md](docs/beacon_validation.md) — how benign and
  malicious beacons were separated.
- [docs/tls_dataset_notes.md](docs/tls_dataset_notes.md) — why the TLS
  classifier was built, measured, and rejected for a rule.
- [docs/ddos_validation.md](docs/ddos_validation.md) — the SYN-flood pcap and
  what Zeek made of it.
- [docs/latency.md](docs/latency.md) — detection-latency distribution.
- [docs/throughput.md](docs/throughput.md) — throughput and the limits of the
  number.

## Repository layout

```
src/
  pipeline.py          the orchestrator — merges the logs, runs the detectors
  ingest/              follow() a Zeek JSON log; adapt CIC-IDS2017 CSV rows
  features/            sliding window, DNS lexical + dictionary features, TLS
  detectors/           the six detectors
  alerts/              Alert schema, incident aggregation, SQLite store
dashboard/
  api.py               FastAPI, read-only over the SQLite file
  replay.py            paced capture replay + pipeline process
  index.html           single-file React dashboard, no build step
scripts/               Zeek wrapper, dataset builders, training, throughput
docs/                  models, validation, throughput, latency
data/                  models/ committed; raw captures gitignored
```

## Honest limitations

Every detector's blind spot is written down, not hidden — an exfiltration over
SCP evades the exfil detector, malware on an allowlisted TLS fingerprint passes
the encrypted-session detector, C2 responses padded above 4 KB evade the beacon
filter. The full list, per detector, is at the end of
[docs/models.md](docs/models.md). A judge who asks how to evade the system
should find the answer already written.
