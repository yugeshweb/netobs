# Throughput

Constraint (d) asks for a defined throughput target and the traffic rate
tested against. This is that measurement.

The short version: the pipeline sustains **about 10,000 records per second**
against arriving traffic on the hardware below, at a per-source sliding-window
occupancy of roughly 3,600 flows. That number is meaningless without the
occupancy, and §6 explains why it does not transfer to a live link running at
10,000 flows/s.

---

## 1. Hardware

| | |
|---|---|
| CPU | Intel Core i9-13900HX, 32 logical cores |
| RAM | 7.8 GB visible to WSL2 (host has 16 GB; WSL2 takes half by default) |
| OS | Ubuntu 24.04 under WSL2, kernel 6.18.33.2-microsoft-standard-WSL2 |
| Python | 3.12, CPU only — no GPU is used anywhere in this project |
| Storage | ext4 on the WSL virtual disk |

The feeder and the pipeline run as separate processes on this one machine.
With 32 logical cores and two mostly single-threaded processes there is
little contention, but it is not a two-machine measurement and should not be
described as one.

## 2. What is being measured

The pipeline reads Zeek logs that another process appends to. If it is
slower than the writer, nothing is lost — a backlog builds in the file and
the pipeline falls behind. So:

> **Keeping up at rate R** means the backlog stays flat while records arrive
> at R. Falling behind means it grows without turning over.

Backlog comes straight out of `/proc/<pid>/fdinfo`: the pipeline's own file
offset against what the feeder has written, mapped back to an exact record
count through a table of record byte offsets. Nothing in `src/` is
instrumented or modified for any of this. Buffered reads mean the offset
leads true progress by up to one buffer, about 8 KB or 15 records — a
constant, so it does not affect whether the backlog grows.

Two rates are reported:

- **capacity** — feed everything at once and measure how fast the pipeline
  gets through it. This is the ceiling.
- **sustained** — feed at a fixed rate and check the backlog holds level.
  This is the honest operating figure, and it comes out at roughly 85% of
  capacity.

Run it with `scripts/throughput.py`; `--occupancy` reports window occupancy
without starting a pipeline at all.

## 3. Controls

**The feeder is not the bottleneck.** With no pipeline attached it writes
**1,039,170 records/s** — about 100× the fastest pipeline rate measured here,
so every limit below is the pipeline's. It batches flushes into roughly 20 ms
chunks; flushing per record, as the demo replay feeder does, would cap the
writer well below the rates tested.

**Startup is excluded.** The pipeline spends 1.0–2.8 s importing lightgbm and
loading the DGA model before it reads its first record. Measurement begins
when the read offset first moves.

**Peak RSS** stayed between 175 MB and 219 MB across every run, including
those holding a 4-day window. Memory is not a constraint at this scale.

## 4. Capacity against window occupancy

This is the result that matters, and it was not the result expected.

The detectors compute features every 25th connection over the sliding window
**for that one source**, so the cost per record is set by how many flows one
source has in the window — not by the record rate. Occupancy was dialled by
varying `--span`, and measured directly by replaying the window logic offline.

| capture | span (s) | mean per-source window | capacity (rec/s) |
|---|---:|---:|---:|
| CTU-354 | 300 | 7.5 | 103,005 |
| CTU-354 | 1,800 | 41.8 | 69,837 |
| CTU-354 | 7,200 | 164.2 | 79,966 |
| CTU-354 | 28,800 | 636.2 | 50,470 |
| **Neris** | **30** | **655.9** | **45,001** |
| CTU-354 | 86,400 | 1,824.7 | 22,222 |
| CTU-354 | 172,800 | 3,621.6 | 11,806 |
| **Neris** | **300** | **4,204.8** | **13,087** |
| CTU-354 | 345,600 | 6,908.3 | 6,651 |
| **Neris** | **1,800** | **7,509.0** | **7,350** |

Conn records only, so records are flows one for one.

**Two unrelated captures land on the same curve.** CTU-354 at occupancy 636
gives 50,470 rec/s; the Neris capture at occupancy 656 gives 45,001. At the
other end, 6,908 → 6,651 against 7,509 → 7,350. Different traffic, different
spans, agreement within about 12% — which is roughly the run-to-run variance.
Occupancy, not the capture, is what governs the rate.

Above about 600 flows the relationship is roughly inverse — capacity ×
occupancy lands between 29.5 M and 55.2 M, averaging 43 M. That is a ±30%
spread, so treat it as a trend, not a law. Below 600 flows the curve
flattens into fixed per-record costs and the ordering stops being reliable
(1,800 s measured slower than 7,200 s, which is noise, not signal).

## 5. Sustained rate

Fed at a constant rate, with the backlog watched while records were still
arriving. Judging after the feed ends is wrong — the pipeline catches up and
a run that fell badly behind looks level.

At occupancy 3,622 (CTU-354, span 172,800), capacity 11,806:

| offered (rec/s) | consumed | backlog growth | verdict |
|---:|---:|---:|---|
| 8,000 | 8,021 | −21/s | keeps up |
| 10,000 | 9,886 | +112/s | keeps up, marginal |
| 11,000 | 10,724 | +272/s | falls behind |
| 12,000 | 11,296 | +707/s | falls behind |
| 14,000 | 11,177 | +2,392/s | falls behind |

At occupancy 6,908 (CTU-354, span 345,600), capacity 6,651:

| offered (rec/s) | consumed | backlog growth | verdict |
|---:|---:|---:|---|
| 3,000 | 3,005 | −4/s | keeps up |
| 5,000 | 4,998 | +4/s | keeps up |
| 6,000 | 5,937 | +63/s | keeps up, marginal |
| 7,000 | 5,901 | +1,099/s | falls behind |
| 9,000 | 5,708 | +3,290/s | falls behind |
| 11,000 | 5,874 | +5,126/s | falls behind |

The knee is sharp and sits at about 85% of capacity in both cases. Each run
fed for 60–90 seconds, long enough that the 1–3 s of startup is under 5% of
it.

**At the real operating point** — the Neris capture at its actual `--span 300`,
all three logs, so conn plus DNS plus TLS — capacity is **10,363 rec/s**
(three runs: 9,626 / 11,191 / 10,272). Conn alone at the same span is 13,087,
so DNS and TLS handling costs roughly 20%. Applying the 85% knee gives a
sustained figure a little under 9,000 records/s, consistent with the 10,000
measured directly at the nearby occupancy of 3,622.

Run-to-run variance is ±8% on short runs (41k records, ~4 s) and ±0.6% on the
60-second runs. Quote the long ones.

## 6. What this number does not mean

**It is not a claim that the system handles a 10,000 flow/s link.**

The captures available are sparse: Neris is 41,246 records over 3.4 hours,
3.4 records/s. Replaying it at 600× produces 2,000 records/s of wall-clock
throughput while the detectors still only ever hold 300 seconds of *sparse*
traffic. A live link actually carrying 10,000 flows/s would put far more into
the same 300-second window, and §4 shows capacity falls roughly as 1 over
occupancy once past a few hundred flows.

Taking that seriously: if one source dominates the traffic, its window holds
about `300 × R` flows at R flows/s, and capacity is about `43,000,000 /
occupancy`. Setting those equal gives a self-consistent sustainable rate of
**a few hundred flows per second** — around 380, with the ±30% spread in the
constant putting it somewhere between 310 and 430.

That is the number to quote for a live link dominated by one busy host, and
it is much smaller than the replay figure. Traffic spread evenly across many
source IPs keeps per-source occupancy low and sits much higher up the curve.
The Neris capture is the pathological case by construction: a single infected
host running a horizontal scan reaches a per-source window of 15,630 flows.

Fixing this means making `features_for()` incremental rather than recomputing
over the whole window, which is a real piece of work and is not done.

## 7. Two measurement artifacts found on the way

**The pipeline's own printed throughput is not a throughput.** It reports
`elapsed = wall − start − idle_timeout`, subtracting one idle timeout. But
`merged()` follows each log with its own generator and advances them one at a
time, so it waits out a full idle timeout *per log* before returning. The same
run over the same data reports:

| `--idle-timeout` | printed rate |
|---:|---:|
| 1 | 5,807 rec/s |
| 5 | 3,152 rec/s |
| 10 | 1,602 rec/s |

Identical work. The ~2,950 rec/s that used to be quoted in CLAUDE.md came
from this and understated the pipeline by roughly 3×. Nothing here uses the
pipeline's self-report.

**A quiet log stalls the whole pipeline.** Because `merged()` advances one
generator at a time, exhausting a sparse log blocks everything for a whole
`idle_timeout` while nothing is processed. Measured on Neris: 20.0 s of dead
time at `--idle-timeout 10`, 1.5 s at 1 — exactly (logs − 1) × idle_timeout.
In a paced replay it shows up as a flat spot: the pipeline froze for 10 s at
`ssl.log`'s exhaustion, then burst through 11,259 records catching up.
Correctness is unaffected, since the records are still in the file, but
detection latency is not. Phase 8 item 2 should measure that directly.

## 8. Reproducing

```bash
# window occupancy, no pipeline
python3 scripts/throughput.py --logdir data/raw/botnet/zeeklogs \
        --kinds conn --span 300 --occupancy

# capacity: feed everything at once
python3 scripts/throughput.py --logdir data/raw/botnet/zeeklogs --span 300

# sustained: hold a constant rate and watch the backlog
python3 scripts/throughput.py --logdir data/raw/throughput/ctu354 \
        --kinds conn --limit 600000 --span 172800 --rate 10000

# feeder ceiling control
python3 scripts/throughput.py --logdir data/raw/throughput/ctu354 \
        --kinds conn --limit 400000 --no-pipeline
```

The long runs need `data/raw/throughput/ctu354`, built once from the
Stratosphere logs, which ship as TSV rather than JSON:

```bash
python3 scripts/zeek_tsv_to_json.py \
        data/raw/tls_logs/malicious/CTU-Malware-Capture-Botnet-354-1 \
        data/raw/throughput/ctu354
```

1,379,750 conn records, none unparseable. Note it has no `dns.log`, so the
DGA detector sits idle — which is why the operating-point figure in §5 uses
Neris with all three logs.

Stop the dashboard before measuring; uvicorn polling the database once a
second is small but it is not nothing.
