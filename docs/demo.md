# Demo runbook

A rehearsed script for showing NetObs live: the order to run things, the story
for each finding, and honest answers to the questions a judge will ask. Every
number here was measured on this machine; where a claim has a limit, the limit
is stated so a hard question lands on an answer that is already written down.

## The one-line pitch

A passive, read-only sensor for an air-gapped monitoring enclave that detects
all six required threat classes from mirrored traffic alone — no probing, no
decryption, no return path — and shows labelled, evidence-backed alerts on a
live dashboard.

## Setup (once, before the room)

```bash
. venv/bin/activate
cd dashboard && uvicorn api:app --port 8000        # NOT --reload
```

Open <http://localhost:8000> in the Windows browser. The board loads the
shipped `alerts.db` — the Neris capture already processed, **225 alerts, 14
incidents** — so there is something real on screen before you touch anything.
Hard-refresh (Ctrl+Shift+R) if a stale tab shows "offline".

Have four captures ready in the replay dropdown: the Neris botnet capture, and
the three lab captures (`ddos`, `exfil`, `dnstunnel`).

## Six-class coverage — which capture shows which

| PS | class | shown by | fires as |
|----|-------|----------|----------|
| a | Volumetric DDoS | `ddos.pcap` | `syn_flood`, medium |
| b | C2 beaconing | Neris | 5 beacons, 184.82.x.x |
| c | DGA domains | Neris | `dga_domain`, critical |
| c | DNS tunnelling | `dnstunnel.pcap` | `dns_tunnel`, high |
| d | Encrypted-session malware | Neris | `encrypted_malware` |
| e | Reconnaissance | Neris | `port_scan`, critical |
| f | Data exfiltration | `exfil.pcap` | `exfiltration`, high |

Neris carries four of the six on its own, which is why it is the centrepiece;
the three lab captures cover the rest and reinforce.

## Flow

### 1. Open on the Neris board (no setup, ~2 min of talking)

Fourteen incidents from one infected host (147.32.84.165) in a 2011 CTU-13
capture. Walk the top of the list — it is ordered most-serious first:

- **Reconnaissance, critical, 178 observations over 3.3 hours.** A horizontal
  scan across 92 hosts on 6 ports, failed-ratio 0.989, small-flow-ratio 0.994.
  Point at the evidence panel: this is a rule, so it states exactly what it saw.
  Zero false positives across the whole capture.
- **DGA domain, critical, confidence 1.00.** `hcuewgbbnfdu1ew.com`, with ten
  domains accumulated under the one host. This is the LightGBM model, and the
  headline: it was trained entirely on *synthetic* domains and caught real 2011
  malware domains at high confidence. `kjjhzhsy.com` (0.89) is a second genuine
  hit; `103092804.com` (queried as `ad.103092804.com`) is probably an ad
  network — a likely false positive, and it is in the list honestly.
- **C2 beaconing — five destinations** in the 184.82.x.x range, periods 8–14 s,
  each receiving 612–644 bytes per check-in. The story worth telling
  (finding #3): timing did *not* separate these from benign beacons — the
  benign fixed-schedule beacons were *more* regular. The discriminator is the
  short inbound response: a C2 check-in gets a command, a benign beacon gets
  content. Show one beacon's evidence: period ~8 s, mean inbound ~610 bytes.
- **Suspicious TLS.** Several observations, mostly in the low/observe band on
  purpose — an unrecognised JA4 fingerprint alone is weak evidence. This is the
  detector where a classifier was built and *rejected* (see Q1 below); say so,
  it is a strength not a gap.

Point out the confidence meters and the traffic-clock timeline — everything is
scored on time read from the capture, so 2011 traffic is aged correctly.

### 2. (Optional) Replay Neris live at 60×

If you want to show streaming rather than a finished board: pick Neris, 60×,
Start. Incidents appear progressively over ~3.5 minutes while you talk. The
point to make: **the replay reproduces the batch run alert-for-alert, 225/14,
byte-identical** — the system is deterministic, not theatre. A replay rebuilds
`alerts.db`, so this also resets the board.

### 3. DDoS — replay `ddos.pcap` (30×)

A real hping3 SYN flood (generated on loopback) plus benign traffic in one
capture. Fires one `syn_flood` incident on the target: `incomplete_ratio 1.0`,
28,315 spoofed sources, `source_spread 1.0`. The benign connections in the same
capture stay silent. Honest note (finding #14): it scores *medium*, not
critical — the confidence encodes that this is definitely a spoofed flood, not
how hard it is hitting. Detail in [ddos_validation.md](ddos_validation.md).

### 4. Exfiltration — replay `exfil.pcap`

One `exfiltration` incident, high (0.88): 118 MB outbound to one destination,
zero inbound, over port 9000. The normal browsing to a different destination in
the same capture does not fire — the detector judges per-destination, so a
balanced-looking host is still caught once you split by where the bytes went.

### 5. DNS tunnelling — replay `dnstunnel.pcap`

One `dns_tunnel` incident, high (0.78): `tunnel-c2.net`, mean subdomain length
37 characters, high subdomain entropy, mostly TXT records. The DGA half of the
same detector correctly stays silent — `tunnel-c2.net` is a pronounceable name,
so it is caught as a tunnel, not misclassified as a generated domain.

### 6. The false-positive control — replay a benign capture

Replay `benign_beacon.pcap` (or `benign.pcap`): **zero alerts.** This is the
most important slide for credibility — the benign fixed-schedule beacons are
*tighter* in timing than the real C2, and the system still does not fire on
them. Say the sample is small (4 destinations, 10 minutes) and that a larger
benign capture is the honest next step.

### Reset between runs

Each replay rebuilds `alerts.db`. To get back to the full Neris board:

```bash
python3 src/pipeline.py --logdir data/raw/botnet/zeeklogs    # rebuild, 225/14
# or, to restore the shipped copy exactly:
git checkout data/alerts.db
```

## The hard questions, answered

**Q1. Why is the TLS detector a rule and not ML?** Because we tried ML and it
failed honestly. A LightGBM classifier on 67,342 TLS sessions reached 0.9951
accuracy — then the feature importances showed it was reading the server name
(`sni_entropy`, `sni_length`), duplicating the DGA detector. Strip the lexical
SNI features and ROC AUC falls to 0.4918, chance. Malware using a valid
certificate and a normal TLS client is not separable on handshake metadata
alone. So the shipped detector is a JA4 allowlist plus structural red flags.
[tls_dataset_notes.md](tls_dataset_notes.md), finding #4.

**Q2. What is your false-positive rate?** Per detector, with sample sizes, not
one headline: beaconing 0 on 319 benign flows; reconnaissance 0 across the
whole Neris capture; exfiltration ignored the benign browsing in its capture;
the benign captures produced 0. The DGA model at the 0.85 operating point has
FPR 0.0095 on 25,000 held-out domains. The honest caveat: the benign captures
are small, so these are "no false positives observed", not a rate.

**Q3. How would you evade this system?** Every detector's blind spot is written
down. Exfiltrate over SCP and the exfil detector skips it (it ignores known
upload ports — a deliberate trade). Use a TLS client whose fingerprint is on
the allowlist and the encrypted-session detector passes you. Pad your C2
responses above 4 KB inbound and the beacon filter lets them through. The
collected list is at the end of [models.md](models.md).

**Q4. Is it really real-time?** Detection latency, sensor-to-stored-alert, is
p50 0.076 s and p99 0.68 s on Neris at 60× — a distribution, not a mean.
[latency.md](latency.md). It processes ~10,000 records/s in replay; the
live-link figure is lower and governed by per-source window occupancy, and we
state both rather than quoting the flattering one. [throughput.md](throughput.md).

**Q5. The DGA model was trained on synthetic domains — does it work on real
malware?** Yes, and the demo is the proof: trained only on synthetic families,
it caught two genuine 2011 Neris DGA domains at 1.00 and 0.89 confidence.
Wordlist-family recall is 0.53, which is the hard case and we do not hide it.
[dga_operating_point.md](dga_operating_point.md).

**Q6. How is this read-only / how do you guarantee no pivot back?** By
construction: the only input is a set of log files another process appends to.
There is no socket, no probe, no query to the source anywhere in the code path.
A compromised NetObs box cannot reach the production network because it has
nothing to reach it with.

**Q7. Why do some real threats score medium or low?** Because confidence is
calibrated to evidence strength, not drama. A DDoS scores medium because the
score means "definitely a spoofed flood", not "N× normal" (finding #14). A lone
unrecognised TLS fingerprint sits in the observe band because, on a network of
hundreds of legitimate apps, it is genuinely weak evidence. Over-alerting is how
a monitoring system gets ignored.

## If a replay misbehaves mid-demo

- Board stuck on "offline": hard-refresh (Ctrl+Shift+R). The socket
  auto-reconnects every 2 s.
- Nothing appears: check `tail -f data/replay/pipeline.log`; confirm the
  capture is in the dropdown and Zeek converted it.
- Never run `uvicorn --reload` — it restarts on replay log writes and kills the
  socket.
