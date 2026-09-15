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
