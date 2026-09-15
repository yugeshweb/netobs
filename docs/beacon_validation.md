# C2 beacon detector: validation

## Method

Two captures, same detector, no per-dataset tuning.

- **Malicious**: CTU-13 Scenario 2 (Neris), 40,198 flows, botnet traffic only.
- **Benign**: 10-minute local capture, 319 flows, four destinations beaconing
  on fixed schedules (10s, 15s, 20s +/-20% jitter, 30s) to mimic update
  checkers and telemetry agents.

## Result

| capture   | alerts | interpretation      |
|-----------|--------|---------------------|
| benign    | 0      | 0 false positives   |
| malicious | 5      | C2 destinations found |

## What separated them

Timing did not. Benign beacons reached gap CVs of 0.021-0.052, tighter than
the malicious ones at 0.24-0.29. An earlier version of this detector using
timing and request-size alone produced 2 false positives on the benign set.

The discriminator is **mean inbound bytes per contact**:

- malicious C2: 612-643 bytes, tightly clustered
- benign beacons: 7,101 and 126,357 bytes

A C2 check-in receives a short command response. A benign beacon fetching
content receives the content. A 4 KB inbound ceiling separates them cleanly.

## Limits

- Benign set is 4 destinations over 10 minutes. Small. A larger and more
  varied benign capture is needed before quoting a false-positive rate.
- An attacker who pads C2 responses above 4 KB would evade this filter.
- Malicious set contains botnet traffic only, so no benign traffic was
  present to be misclassified within it.
