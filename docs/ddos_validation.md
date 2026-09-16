# DDoS on a real pcap

The DDoS detector had only ever run through the CIC-IDS2017 CSV adapter. The
CSV path and the Zeek path produce different connection states — the CIC
Friday attack is LOIC, mostly completed connections (the application-layer
path), while a SYN flood is half-open connections (the volumetric path) — and
the volumetric path had never seen real Zeek output. This closes that gap.

## What was generated

`scripts/make_ddos.sh`, on loopback, one pcap with three segments:

1. ~30 completed HTTP connections to `127.0.0.1:8080` (benign, before)
2. a 20 s SYN flood to `127.0.0.2:80`, `hping3 --rand-source -S -i u666`
   (~1,500 pps, a fresh spoofed source per packet)
3. ~30 completed HTTP connections again (benign, after)

The flood and the benign traffic go to different `(dst, port)` keys, which the
detector tracks separately, so the same capture shows it firing on one and
silent on the other. Needs root for `tcpdump` and raw sending; run the script
directly and give sudo the password once.

## What Zeek saw

28,375 connections. The real kernel's response to the spoofed flood was a mix,
which is the empirical fact worth having:

| state | count | meaning |
|---|---|---|
| S0 | 26,934 | SYN seen, no reply — half-open |
| REJ | 1,381 | SYN then RST — refused |
| SF | 60 | benign, completed |

Both S0 and REJ are in the detector's `INCOMPLETE` set, so the flood's
`incomplete_ratio` is 1.0. 28,315 of the connections went to `127.0.0.2:80`
from 28,315 distinct sources; the 60 SF went to the benign port. The flood
spanned 22.2 s at a true mean rate of ~1,274/s.

## What fired

One incident, keyed on the target, and nothing else — the only alerts in the
run were `ddos`:

```
ddos | medium | 3010 sources -> 127.0.0.2 | peak 0.68
  pattern: syn_flood        incomplete_ratio: 1.0
  target_port: 80           small_flow_ratio: 1.0
  flows_per_sec: 100.3      source_spread: 1.0
  baseline_per_sec: null    distinct_sources: 3010
  spike_ratio: null
```

`syn_flood` because incomplete > 0.9; `baseline_per_sec: null` because the
volumetric path takes no baseline — half-open connections are abnormal by
definition; `source_spread: 1.0` from the fully random sources. **The 60
benign SF connections produced no alert.** This is the first time the
volumetric path has been confirmed on real Zeek output rather than the CSV
adapter, and it fired on a real S0/REJ mix.

## The confidence is medium, and why that is honest

The flood ran at ~1,274/s, but the detector reported `flows_per_sec: 100.3`
and scored 0.68 (medium), not critical. That is not an error and it is not a
number to tune — it is how the detector is built, and the run is what made it
visible.

`check()` fires on the first sample where `rate >= min_rate` (100/s), and rate
is `n / span` over the fixed 30 s window. So it fires the instant the window
has accumulated `min_rate × span ≈ 3,000` flows, at which point `flows_per_sec`
is by construction ~100 regardless of how hard the flood is actually hitting.
The 60 s cooldown then suppresses re-fires, so there is no later sample with a
denser window to raise it. Confidence is
`0.4·intensity + 0.35·shape + 0.25·spread`; with intensity pinned near
`min(1, 100/500) = 0.2` at first fire, the score is carried by shape
(incomplete = 1.0) and spread (1.0), which is why it lands at
`0.08 + 0.35 + 0.25 = 0.68` every time.

So the confidence encodes *"this is definitely a spoofed-source flood"* — via
the two terms that saturate — not *"this flood is N× normal"*. That is a
reasonable thing for it to mean, but it means a 1,500/s flood and a 150/s one
score the same. Reporting peak intensity instead would need the detector to
keep sampling through the cooldown and carry the maximum, which it does not do.
Left as-is: the detector's job is to flag the flood with evidence, and it does.

An earlier prediction in the plan that a 1,500 pps flood would fire *critical*
was wrong for exactly this reason — it assumed the reported rate would track
the send rate.

## Both detection paths are now covered on real-ish data

| path | traffic | states | pattern | source |
|---|---|---|---|---|
| volumetric | SYN flood, this run | S0 + REJ | `syn_flood` | Zeek, real pcap |
| application | CIC Friday DDoS | mostly SF | `application_flood` | CIC CSV adapter |

The application-layer path (LOIC, completed connections, fires on rate ≥ 5× a
target's own baseline) is still only measured through the CSV adapter; a real
pcap for it would need a completed-connection flood generator, not hping3.

## A synthetic pre-check exists too

Before the sudo run, `data/raw/ddos/synthetic.pcap` was crafted in userspace
with scapy `wrpcap` (no root) — pure S0 flood plus benign SF — and gave the
same result: one `syn_flood` at 0.68, benign silent. It confirmed the
Zeek→detector wiring without needing capabilities, but it is not a substitute
for the real run, because it cannot show what conn states the kernel actually
produces. The real run's S0/REJ mix is exactly what it could not have told us.

## Reproducing

```bash
./scripts/make_ddos.sh                     # sudo; writes data/raw/ddos/ddos.pcap
./scripts/run_zeek.sh data/raw/ddos/ddos.pcap data/raw/ddos/zeeklogs
python3 src/pipeline.py --logdir data/raw/ddos/zeeklogs --span 30 \
        --db data/raw/ddos/real.db
```
