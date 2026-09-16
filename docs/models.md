# Models, features, and validation

This document covers, for each of the six threat classes, what model or rule
detects it, what features it works from, how it was trained and validated, and
where it is blind. Each section links to the detailed document for that detector rather
than repeating it; this file carries the headline and the pointer.

## The design principle

**Rules where the behaviour is definitional, models where it is genuinely
statistical.** A port scan is one sentence — one source, many destinations,
mostly failing — so a rule detects it, states exactly which thresholds it
crossed, and generalises to variants a training set never held. A DGA domain is
not definable that way: whether a string looks algorithmically generated is a
statistical judgement over character and word structure, so it earns a model.

Two of the six detectors are models, four are rules. The important detail is
that one of the two models — the encrypted-session classifier — was built,
measured, and **rejected** in favour of a rule, and that rejection is one of the
project's strongest validation results (see (d)).

Every detector, rule or model, emits the same `Alert` record — timestamp, flow
identifier, threat class, confidence, and a free-form evidence dict — defined in
`src/alerts/schema.py`. All time-based state runs on the traffic clock (the
newest timestamp seen in the data), never the wall clock, so a 2011 capture is
scored as 2011.

## At a glance

| # | threat class | detector | type | headline validation | detail |
|----|--------------|----------|------|----------------------|--------|
| a | Volumetric / protocol DDoS | `detectors/ddos.py` | rule | `syn_flood` on a real hping3 pcap; benign control silent | [ddos_validation.md](ddos_validation.md) |
| b | C2 beaconing | `detectors/beaconing.py` | rule | 0 FP on 319 benign flows; 5 C2 in Neris | [beacon_validation.md](beacon_validation.md) |
| c | DGA + DNS tunnelling | `detectors/dns_threat.py` | **model** + rule | held-out ROC AUC 0.9876; 2 real 2011 DGA caught | [dga_operating_point.md](dga_operating_point.md) |
| d | Malware in encrypted sessions | `detectors/encrypted_threat.py` | rule (model rejected) | SNI-free classifier AUC 0.4918 → rule shipped | [tls_dataset_notes.md](tls_dataset_notes.md) |
| e | Reconnaissance / port scanning | `detectors/port_scan.py` | rule | 178 obs → 1 incident, 0 FP on Neris | — |
| f | Data exfiltration | `detectors/exfiltration.py` | rule | fires on lab exfil, ignores same-capture browsing | — |

Constraints (c) near-real-time and (d) throughput are measured in
[latency.md](latency.md) and [throughput.md](throughput.md).

---

## (a) Volumetric / protocol DDoS — rule

**Model:** none. Keyed on the **target**, not the source — a spoofed flood has
thousands of sources, so keying by source would produce thousands of incidents
for one attack.

**Features**, per `(dst, port)` over a 30 s window: `incomplete_ratio` (share of
connections in states `S0, REJ, RSTOS0, SH, S1`), `small_flow_ratio`, the
target's own rate against a rolling **median baseline** (median, not mean, so a
single spike does not raise "normal"), and **source-IP entropy** normalised to a
0–1 spread by dividing by `log2(n_sources)` — the source-entropy signal,
scaled so a flood from 10,000 addresses is not
automatically ranked above one from 100.

**Two paths.** Volumetric fires on `incomplete_ratio ≥ 0.7` with no baseline —
half-open connections are abnormal by definition. Application-layer fires on
`small_flow_ratio ≥ 0.7` **and** rate ≥ 5× the target's baseline, because
LOIC-style floods open real, completed connections where incompleteness does not
apply.

**Validation.** The application path was measured on CIC-IDS2017 Friday-DDoS
through the CSV adapter: one `application_flood`, baseline 38.4/s vs current
192.2/s, 3,661 sources, spread 0.935. The volumetric path was then tested on a
**real Zeek pcap** — an hping3 `--rand-source` SYN flood on loopback — which is
the first time it ran on real connection states rather than the adapter: Zeek
classed the 28,315 flood connections 95% `S0` + 5% `REJ`, the detector fired one
`syn_flood` with `incomplete_ratio 1.0` and `source_spread 1.0`, and the 60
benign completed connections in the same capture stayed silent.

**Limitations.** Confidence encodes *shape*, not *magnitude*: because the
detector fires on the first sample crossing `min_rate` and reports `n / span` at
that instant, a 1,500/s flood and a 150/s one both score ~0.68, carried by the
saturated incomplete-ratio and spread terms. The application-layer path is still
only tested through the CSV adapter. Full account and finding #14 in
[ddos_validation.md](ddos_validation.md).

## (b) C2 beaconing — rule

**Model:** none. Tracked per `(src, dst, port)` over a 1800 s window.

**Features:** contact count, inter-arrival **gap CV** (coefficient of
variation), period, and **mean inbound / outbound bytes per contact**. Fires on
≥ 8 contacts, gap CV ≤ 0.35, period 1–900 s, mean out ≤ 8 KB and **mean in ≤ 4
KB**, skipping infrastructure ports (NTP, DHCP, mDNS, SSDP, NetBIOS).

**Validation.** Two captures, no per-set tuning: 40,198 malicious flows (Neris)
and 319 benign flows across four fixed-schedule beacons built to mimic update
checkers. Result: **0 false positives on benign, 5 C2 destinations in Neris**.

The finding that shaped it: **timing alone cannot separate the two.** The benign
beacons were *more* regular than the malware (gap CV 0.021–0.052 vs 0.24–0.29),
and an early timing-plus-size version produced 2 false positives. The
discriminator is mean inbound bytes — malicious C2 612–643 bytes (a short
command response) against benign 7,101 and 126,357 bytes (fetched content). A
4 KB inbound ceiling separates them cleanly.

**Limitations.** Benign set is small (4 destinations, 10 minutes) — no FP rate
should be quoted from it. An attacker who pads C2 responses above 4 KB evades
the filter. Detail in [beacon_validation.md](beacon_validation.md).

## (c) DGA domains + DNS tunnelling — LightGBM model + rule

**Model:** LightGBM classifier, 19 features, for DGA. DNS tunnelling is a
separate rule.

**Features engineered** — 13 lexical (`src/features/dns_features.py`): length,
character entropy, vowel / digit / hex ratios, longest consonant run, longest
digit run, unique-character ratio, label count, has-digit, starts-with-digit,
and bigram / trigram plausibility scores. Plus 6 dictionary-segmentation
(`src/features/word_features.py`): segmentation coverage, word count, longest
word, mean word length, fully-covered flag, and `len_vs_quality` =
trigram-plausibility × (length ÷ 12). That last feature is what attacks the hard
family — a name both long *and* statistically plausible is the wordlist-DGA
signature — and it ranked third in importance; adding the dictionary features
moved wordlist recall 0.63 → 0.77 while *cutting* false positives.

**Training.** 100,000 rows: 50k Tranco benign, 50k synthetic DGA across three
families (`dga_random` and `dga_hash` are easy; `dga_wordlist` is deliberately
hard, mirroring Suppobox / Matsnu, so the model cannot learn "weird letters mean
bad"). The split is done **first**, then the n-gram plausibility models are fit
on **training-set benign labels only** — fitting them on all the data would leak
test information into every row's bigram / trigram feature.

**Validation.** 25,000 held-out domains: accuracy 0.9365, ROC AUC 0.9876,
per-family recall `dga_hash` 1.0000 / `dga_random` 0.9928 / `dga_wordlist`
0.7671. Operating point **0.85 alert / 0.60 observe**, chosen at the knee where
false positives stop falling fast (full threshold table in
[dga_operating_point.md](dga_operating_point.md)). The real validation: a model
trained entirely on synthetic domains caught two genuine 2011 Neris malware
domains — `hcuewgbbnfdu1ew.com` (conf 1.00) and `kjjhzhsy.com` (0.89).

Two input-validation rules mattered as much as the model: skip single-label
NetBIOS/mDNS names (before this, 63 alerts were essentially all `workgroup`),
and score the *parent* domain, not the full query, so a tunnel is not
misclassified as a DGA.

**DNS tunnelling (rule).** Per-source 120 s window: ≥ 40 queries, ≥ 60% to one
parent domain, mean subdomain length ≥ 25, subdomain entropy ≥ 3.0. Confidence
weights volume (scaled against the query floor — a *slow* tunnel is evasive, not
benign), subdomain length and entropy, unique-subdomain ratio, and
high-capacity qtype share (TXT/NULL/CNAME/MX/SRV). Measured 0.82 on the
generated tunnel; the DGA half correctly stayed silent on the pronounceable
tunnel host.

**Limitations.** Dictionary-DGA recall is 0.53 at the operating point, in line
with the known difficulty of those families. The DGA classes are synthetic —
the held-out figures are not a claim about real-world malware, only the two real
Neris hits are.

## (d) Malware in encrypted sessions — rule, after a model was rejected

This is the detector where a classifier was built, measured, and **thrown away**
— and that is the point worth reading.

**First model:** LightGBM on 67,342 TLS sessions from 23 captures, split **by
capture** so held-out families were unseen. It reached 0.9951 accuracy. Reading
the feature importances showed why: it was driven by `sni_entropy`,
`sni_length`, `sni_digit_ratio` — lexical properties of the server name. It had
learned to spot odd-looking domains, duplicating the DGA detector rather than
adding a capability. **Second model:** removing every lexical SNI feature and
keeping only structural and certificate properties dropped ROC AUC to **0.4918**
— chance. One held-out capture (Botnet-403-1, 3,246 sessions) scored 0.0000 in
both. Conclusion: malware using valid certificates, standard ciphers, ALPN and
legitimate hosts is not separable from a browser on handshake metadata alone,
because its TLS client *is* a normal TLS client.

**Shipped detector (rule).** JA4 client fingerprinting against a site-configured
allowlist of verified software, plus structural red flags — no SNI, self-signed
or invalid certificate, subject equals issuer, unknown issuer, TLS on a
non-standard port — each contributing to a score, with two bands (alert 0.45,
observe 0.22). Measured: 0 alerts on 151 benign curl sessions, 30 on Neris, and
the 2021 sample correctly landing in the *observe* band, not an alert.

The dataset work behind this is itself validation methodology: captures were
excluded for **schema leaks** (a `validation_status` field present in every
malicious capture and absent in four benign ones would have let a model learn
the schema) and **label noise** (a 19-day capture labelled malicious in its
entirety was 77% ordinary Firefox traffic, and its 0.4839 score against 0.98+
elsewhere was hidden by the 0.80 average). Features deliberately exclude TLS
version and raw cipher identity, which encode the capture *era* rather than
threat. Full account in [tls_dataset_notes.md](tls_dataset_notes.md).

**Limitation.** Malware whose fingerprint matches an allowlisted client passes
unnoticed. Production deployments pair the allowlist with threat-intelligence
feeds of known-bad fingerprints; that feed is out of scope here.

## (e) Reconnaissance / port scanning — rule

**Model:** none. Fan-out from one source, over the sliding window.

**Features:** flow count, distinct destination ports, distinct destination
hosts, `failed_ratio`, `small_flow_ratio`, port entropy. Fires on `n_flows ≥
20`, `failed_ratio ≥ 0.5`, `small_flow_ratio ≥ 0.6`, and either `≥ 30` ports
(vertical) or `≥ 15` hosts (horizontal); both is hybrid. Confidence blends how
far past threshold the fan-out reached, flow-count support, and the mean of the
two ratios.

**Validation.** On Neris: **178 observations → 1 incident, 0 false positives** —
a `horizontal_scan` across 92 hosts on 6 ports, `failed_ratio 0.989`,
`small_flow_ratio 0.994`, peak confidence 1.00, sustained 3.3 hours.

**Limitation.** Measured on one malware-only capture; no benign-traffic FP
figure. `min_ports` had to be raised from 15 to 30 after a clear horizontal scan
was mislabelled hybrid — a reminder the thresholds are capture-informed.

## (f) Data exfiltration — rule

**Model:** none. Judged **per destination**, not per source — a host that
downloads all day and uploads one file to one address looks balanced in
aggregate but obvious once split by destination.

**Features:** outbound bytes, out/in byte ratio, flow count to a single
destination. Fires on `out_bytes ≥ 5 MB`, `out/in ≥ 3.0`, `flows ≥ 3`. The 5 MB
floor is what kills noise: an out/in ratio of 172 across two tiny flows is
meaningless, so a ratio needs volume behind it. Known upload ports (FTP, SSH,
rsync, SMB, NFS: 20, 21, 22, 873, 445, 139, 2049) are skipped, because those are
*supposed* to carry heavy uploads.

**Validation.** On lab exfil traffic at default thresholds (no tuning to pass):
58.5 MB out, 0 in, 3 flows to port 9000, confidence 0.81 — and the normal
browsing to a different destination in the same capture did not fire.

**Limitations.** The upload-port skip list is a **deliberate blind spot**: an
attacker using SCP evades it entirely. Stated plainly rather than hidden. Never
tested against benign traffic, and the exfil is loopback-generated, not a real
transfer.

---

## Cross-cutting validation lessons

Two things are methodology, not per-detector, and are why the numbers above are
trustworthy:

- **When a model scores suspiciously well, read the feature importances.** The
  0.9951 TLS classifier was a domain-name classifier in disguise. Accuracy did
  not reveal that; importance did.
- **Look per class and per capture, never at the average.** An 0.80 headline hid
  both 0.98+ on seven captures and 0.48 on one noisy 19-day capture. The average
  is where problems go to hide.

Neither the DGA operating point nor the beacon discriminator was picked to make
a test pass — the exfiltration detector finding *nothing* in Neris was accepted
as correct (the capture had no exfil in it) rather than lowered to force a hit.

## Constraints (c) and (d)

- **Near real time (c).** Detection latency, sensor-to-stored-alert on Neris at
  60×: p50 0.076 s, p99 0.678 s, max 2.403 s, reported as a distribution rather
  than a mean. This was 57 s at p99 before a merge fix that separated "a log is
  quiet" from "a log has ended." Method and before/after in
  [latency.md](latency.md).
- **Throughput (d).** ~10,000 records/s sustained against arriving traffic at
  the Neris operating point, with the honest caveat that the figure is governed
  by per-source window occupancy and does not transfer unchanged to a live
  10,000-flow/s link. Full method, controls and every table in
  [throughput.md](throughput.md).

## Limitations, collected

For the "how would you evade this?" question, in one view:

| detector | blind spot |
|----------|------------|
| DDoS (a) | confidence reflects flood shape, not magnitude; app-layer path CSV-tested only ([ddos_validation.md](ddos_validation.md)) |
| C2 beacon (b) | pad responses above 4 KB inbound; benign set is small ([beacon_validation.md](beacon_validation.md)) |
| DGA (c) | wordlist-family recall 0.53; classes are synthetic ([dga_operating_point.md](dga_operating_point.md)) |
| Encrypted (d) | malware on an allowlisted fingerprint passes; needs a known-bad feed ([tls_dataset_notes.md](tls_dataset_notes.md)) |
| Recon (e) | one malware-only capture, no benign FP rate |
| Exfiltration (f) | SCP and other allowlisted upload ports evade it; never benign-tested |

Every one of these is stated in the detector's own documentation as well. An
honest limitation written down beats an inflated claim found out.
