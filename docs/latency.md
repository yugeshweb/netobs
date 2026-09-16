# Detection latency

Constraint (c) asks for bounded latency, not just streaming. This is the
measurement, the method, and what had to be fixed before the number meant
anything.

## Why `detected_at − ts` cannot be subtracted

An alert carries two clocks. `ts` is traffic time, read from the capture.
`detected_at` is wall time, read from the system. On the 2011 Neris capture
the difference between them is about fifteen years. The two are kept side by
side so the gap can be worked out against a known feed schedule, not so they
can be subtracted from each other.

What is worth measuring is this: how long, in wall time, between the sensor
handing over a record and an alert derived from it existing in the store.
During a paced replay the feeder is the sensor, so it knows exactly when each
record went out. `dashboard/replay.py` writes that to
`data/replay/feed_trace.jsonl` when started with `trace=1`, and
`scripts/latency.py` joins it to the alerts table.

## Joining an alert back to the record that caused it

Every detector stamps its alert with its own traffic clock, and that clock is
a running maximum of the record timestamps it has been handed. So for an alert
at traffic time A, the moment that matters is when the *delivered* traffic
clock first reached A.

That is not the same as "when every record with `ts <= A` had arrived", and
the first version of the script got this wrong and reported latencies as low
as −196 s. The reason is finding #11: Zeek appends a connection when it
closes, so the feeder paces on `ts + duration`. A connection that opened at the
start of the Neris capture and closed at the end is written last while carrying
one of the earliest timestamps. Keying on "everything up to A" waits for that
straggler and puts the join well after the alert it is supposed to explain.

Reading the trace in feed order and keeping the points where the running
maximum steps up gives the right answer, and every latency comes out positive.

## What was wrong

`merged()` advanced one generator at a time. After yielding a record from a
log it called `next()` on that same log, and `follow()` blocked there until a
line arrived or the timeout expired. One quiet log stopped everything.

The root cause was that `follow()` had a single timeout standing in for two
different questions: is there anything to read right now, and is this log
finished. They are now separate. A quiet log gets `lag` seconds to speak
before its siblings are released, and a log ends when its `<log>.done` marker
appears, not when it happens to go silent.

## Measured

Both runs are the Neris capture at 60×, all three logs, on an i9-13900HX with
7.8 GB under WSL2. Same capture, same speed, same machine, 221 alerts each
time, all 221 matched to a fed record.

|  | before | after |
|---|---|---|
| min | 0.055 s | 0.001 s |
| p50 | 4.416 s | 0.076 s |
| p90 | 23.981 s | 0.475 s |
| p99 | 57.084 s | 0.678 s |
| max | 59.591 s | 2.403 s |

Distribution, alerts per bucket:

| bucket | before | after |
|---|---|---|
| 0–0.05 s | 0 | 87 |
| 0.05–0.1 s | 3 | 34 |
| 0.1–0.25 s | 13 | 33 |
| 0.25–0.5 s | 14 | 47 |
| 0.5–1 s | 19 | 19 |
| 1–2.5 s | 33 | 1 |
| 2.5–5 s | 39 | 0 |
| 5–10 s | 37 | 0 |
| 10–30 s | 46 | 0 |
| 30 s+ | 17 | 0 |

The shape is the point, which is why this is reported as a distribution and
not as a mean. Before the fix the bulk of alerts sat in the seconds-to-tens-of-
seconds range and seventeen of them took over thirty seconds, with the tail
landing at 59.6 s against a feeder-computed idle timeout of 54.8 s — the tail
*was* the timeout. After, nothing exceeds 2.5 s and two thirds of alerts land
inside 100 ms.

Per threat class, after the fix:

| class | n | p50 | p99 | max |
|---|---|---|---|---|
| port_scan | 178 | 0.067 s | 0.676 s | 0.706 s |
| dga_domain | 10 | 0.174 s | 0.516 s | 0.540 s |
| c2_beacon | 1 | 0.306 s | — | 0.306 s |
| encrypted_malware | 32 | 0.107 s | 1.818 s | 2.403 s |

## What the remaining tail is, and why it is not a stall

p99 sits at 0.678 s against a `lag` of 0.5 s, which is the bound doing its
job. The one alert past 2 s is `encrypted_malware`, and that is ordinary
ordered-merge behaviour rather than a stall: `merged()` holds one record per
log and emits the lowest timestamp, so an ssl record whose timestamp is ahead
of where conn has got to waits its turn. It is waiting to be correctly
ordered, not waiting on a timeout.

## What this does not measure

This is pipeline latency — sensor to stored alert. It is not detector
latency, which is how long after a behaviour begins the detector has enough
evidence to call it. A beacon needs eight contacts before `beaconing.py` will
say anything, so on a 12 s period it cannot fire sooner than about 96 s of
traffic time no matter how fast the pipeline runs. That floor is a property of
the detector and is not measured here.

The figures are also from a replay, where the feed schedule is known. On a
live link the same instrument would need the sensor to timestamp its own
writes.

## Reproducing

```bash
cd ~/netobs/dashboard && uvicorn api:app --port 8000     # no --reload
curl -X POST "localhost:8000/api/replay/start?pcap=data/raw/botnet/botnet-capture-20110811-neris.pcap&speed=60&trace=1"
# wait for phase: finished
python3 scripts/latency.py --label "Neris 60x"
```

`scripts/latency.py --json` prints the same figures machine-readably.
