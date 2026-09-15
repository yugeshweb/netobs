# Encrypted-session detector: dataset notes

## Source

TLS metadata (`ssl.log`) from Stratosphere / CTU captures: 15 malware
captures and 13 normal captures, obtained as published Zeek logs rather than
raw pcaps.

## Exclusions and why

**Four benign captures (CTU-Normal-21, 28, 29, 30)** were excluded for having
a 20-field schema without `validation_status`, while every malicious capture
had 21 fields. Field presence would have correlated perfectly with class,
letting the model learn the schema instead of the traffic.

**CTU-Malware-Capture-Botnet-348-1 (HTBot)** was excluded for label noise.
It is a 19-day capture of a real machine, labelled malicious in its entirety.
Inspection showed 77% of its TLS sessions carried legitimate SNI values such
as `incoming.telemetry.mozilla.org` and `clients1.google.com` — ordinary
Firefox traffic from the infected user's normal browsing. Its published
`.binetflow` has a Label column but every row is empty, so no per-flow ground
truth is available.

This capture alone accounted for 38% of the first test set and scored 0.4839,
against 0.98+ on every other held-out capture. The average of 0.80 concealed
both facts.

## Method note

The train/test split is **by capture, not by row**: held-out captures contain
malware families and benign sources the model never saw during training. A
random row-level split would place sessions from the same capture on both
sides and overstate generalisation.

## Feature design

TLS version and raw cipher identity are deliberately excluded. Both drift over
time, and the malicious captures skew older than the benign ones; a model
using them would learn the capture era. Cipher *properties* (GCM/CBC mode,
RC4 presence, forward secrecy) are retained as security-posture signals.

## Outcome: classifier rejected

A LightGBM classifier was trained on 67,342 TLS sessions from 23 captures,
split by capture so held-out families were unseen.

**First attempt** reached 0.9951 accuracy. Feature importance showed it was
driven by `sni_entropy`, `sni_length` and `sni_digit_ratio` — lexical
properties of the server name. It had learned to recognise odd-looking
domains, duplicating the DGA detector rather than adding a new capability.

**Second attempt** removed all lexical SNI features, keeping only structural
and certificate properties (self-signed, subject equals issuer, known CA,
ALPN, port, cipher mode). ROC AUC fell to **0.4918** — no better than chance.
Held-out capture Botnet-403-1 (3,246 sessions) scored 0.0000 in both versions.

Conclusion: malware that uses valid certificates, standard ciphers, ALPN and
legitimate-looking hosts is not separable from a browser on handshake
metadata alone. Its TLS client is, functionally, a normal TLS client.

## Detector as shipped

`src/detectors/encrypted_threat.py` uses JA4 client fingerprinting against a
site-configured allowlist of verified software, plus structural red flags
(no SNI, self-signed or invalid certificate, subject equals issuer, unknown
issuer, TLS on a non-standard port). Two bands: alert at 0.45, observe at
0.22.

Measured:

| capture                  | sessions | alerts | observations |
|--------------------------|----------|--------|--------------|
| benign (curl, TLS 1.3)   | 151      | 0      | 0            |
| CTU Botnet-410 (2021)    | 2        | 0      | 2            |
| CTU Neris (2011)         | 43       | 30     | 2            |

**Known blind spot.** The 2021 sample connects to real services with a valid
certificate on port 443. Only its unrecognised fingerprint is unusual, worth
0.25, which places it in the observe band rather than raising an alert. This
is correct behaviour — an unrecognised fingerprint alone is weak evidence on
a network running hundreds of legitimate applications — but it means malware
matching an allowlisted fingerprint would pass unnoticed. Production
deployments pair fingerprint allowlists with threat-intelligence feeds of
known-bad fingerprints; that feed is out of scope here.
