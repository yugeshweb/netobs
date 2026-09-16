#!/usr/bin/env python3
"""Follow a Zeek JSON log and yield records as they are written.

A follower has to answer two different questions and they are not the same
question: *is there anything to read right now*, and *is this log finished*.
Conflating them into a single timeout is what made one sparse log stall the
whole pipeline — merged() had no way to skip a quiet log without also giving
up on it for good, so it had to block. Here they are separate:

  block=False   yield IDLE immediately when there is nothing to read, so the
                caller decides how long to wait rather than being held here
  done_marker   a sibling file that says this log will never grow again

The marker is out of band, a `<log>.done` file rather than a sentinel line in
the log itself, so the log stays byte-identical to what Zeek wrote. The batch
run reads the staged file and the replay reads the live one, and those two
being the same bytes is what makes their results comparable.
"""
import argparse, json, time
from pathlib import Path

# A unique object, not None: json.loads can legitimately return None, 0 or ""
# for a well-formed line, and the caller has to be able to tell "nothing to
# read" apart from "a record that happens to be falsy".
IDLE = object()


def _marker_for(path, done_marker):
    if done_marker is None:
        return None
    if done_marker is True:
        return Path(str(path) + ".done")
    return Path(done_marker)


def follow(path, from_start=True, poll=0.2, idle_timeout=None,
           block=True, done_marker=None):
    """Yield dicts from a Zeek JSON log, waiting for new lines as they arrive.

    block=True (default) keeps the original behaviour: sleep here until a line
    shows up, and give up after idle_timeout seconds of silence.

    block=False yields IDLE whenever the log has nothing new, and returns only
    when the log is genuinely finished — its done_marker exists and the file
    has been read to the end. idle_timeout still applies as a safety net for a
    live sensor that has no marker to offer.
    """
    path = Path(path)
    marker = _marker_for(path, done_marker)

    # A log that never appears must not hang the caller either. The same two
    # exits apply here as below: the marker says it is never coming, and
    # idle_timeout is the fallback for a sensor that offers no marker.
    waited = 0.0
    while not path.exists():
        if marker is not None and marker.exists():
            return
        if idle_timeout is not None and waited >= idle_timeout:
            return
        if block:
            time.sleep(poll)
            waited += poll
        else:
            yield IDLE

    with path.open("r") as f:
        if not from_start:
            f.seek(0, 2)
        # Wall clock rather than a count of sleeps. In non-blocking mode the
        # caller does the sleeping, so there is nothing here to accumulate,
        # and even in blocking mode a poll that overruns made the old counter
        # under-report how long the log had really been quiet.
        quiet_since = None
        while True:
            line = f.readline()
            if line:
                quiet_since = None
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
                continue

            # Nothing to read. Decide whether that is temporary or final.
            if marker is not None and marker.exists():
                # The feeder flushes every line before it drops the marker, so
                # if the marker is here the data is on disk. Read once more
                # anyway — the marker could have landed between our readline
                # and this check — and only then call the log finished.
                line = f.readline()
                if line:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            pass
                    continue
                return

            if quiet_since is None:
                quiet_since = time.time()
            if idle_timeout is not None and time.time() - quiet_since >= idle_timeout:
                return

            if block:
                time.sleep(poll)
            else:
                # The caller owns the waiting. It knows what the other logs
                # are doing and we do not.
                yield IDLE


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--log", required=True)
    p.add_argument("--stats-every", type=int, default=2000)
    p.add_argument("--idle-timeout", type=float, default=3.0)
    p.add_argument("--show", type=int, default=3)
    a = p.parse_args()

    start = time.time()
    n = 0
    for rec in follow(a.log, idle_timeout=a.idle_timeout):
        n += 1
        if n <= a.show:
            print(f"  sample {n}: {rec.get('id.orig_h')} -> "
                  f"{rec.get('id.resp_h')}:{rec.get('id.resp_p')} "
                  f"proto={rec.get('proto')} service={rec.get('service')}")
        if n % a.stats_every == 0:
            el = time.time() - start
            print(f"  {n} records, {el:.1f}s elapsed, {n/el:.0f} rec/s")

    el = time.time() - start
    print(f"\ndone: {n} records in {el:.1f}s ({n/max(el,1e-9):.0f} rec/s)")


if __name__ == "__main__":
    main()
