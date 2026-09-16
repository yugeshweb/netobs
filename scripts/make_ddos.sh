#!/usr/bin/env bash
# Generate a SYN-flood capture on loopback so the DDoS detector can be tested
# against real Zeek output, not just the CIC CSV adapter.
#
# The capture has three segments in one pcap, on purpose:
#   1. benign completed connections to 127.0.0.1:8080  (before)
#   2. a spoofed-source SYN flood to 127.0.0.2:80
#   3. benign completed connections again              (after)
# so the same run shows the detector firing on the flood and staying silent on
# ordinary traffic. The flood and the benign traffic go to different
# (dst, port) keys, which the detector tracks separately.
#
# Needs root for tcpdump and for raw packet sending. Run it directly:
#   ./scripts/make_ddos.sh
# and enter your password once when sudo asks.
set -e

OUT=~/netobs/data/raw/ddos
mkdir -p "$OUT" && cd "$OUT"

TARGET=127.0.0.2          # flood target; nothing listens here
FLOOD_PORT=80
BENIGN_PORT=8080
PPS=1500                  # packets/sec; -i u666 ~= 1500/s. Over the 100/s
                          # floor by a wide margin without burying Zeek.
FLOOD_SECS=20

command -v hping3 >/dev/null || {
  echo "hping3 not found. Install it with:  sudo apt-get install -y hping3"
  echo "(or this script will fall back to scapy, which is slower)"
}

echo "== starting benign web service on 127.0.0.1:$BENIGN_PORT =="
python3 -m http.server "$BENIGN_PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
WEB=$!
sleep 1

# tcpdump captures the whole session. -i lo, no snap limit needed for SYNs.
echo "== capturing on lo =="
sudo timeout $((FLOOD_SECS + 30)) tcpdump -i lo -w ddos.pcap 2>/dev/null &
CAP=$!
sleep 3

benign_burst () {
  # ~30 completed connections, a few per second: SF state, well under every
  # DDoS threshold. This is the segment the detector must NOT fire on.
  echo "== benign burst ($1) =="
  for _ in $(seq 1 30); do
    curl -s "http://127.0.0.1:$BENIGN_PORT/" >/dev/null || true
    sleep 0.25
  done
}

benign_burst before

echo "== SYN flood: $PPS pps for ${FLOOD_SECS}s, spoofed sources =="
if command -v hping3 >/dev/null; then
  # --rand-source: a fresh spoofed source per packet, which is what gives the
  # detector its >=25 distinct sources and a high source-spread. -S: SYN only.
  # -i u666: ~1500 pps (no --flood, so the rate stays controlled).
  sudo timeout "$FLOOD_SECS" hping3 --rand-source -S -p "$FLOOD_PORT" \
       -i u666 "$TARGET" >/dev/null 2>&1 || true
else
  # Fallback: scapy sends spoofed SYNs from the venv. Same shape, slower.
  sudo ~/netobs/venv/bin/python3 - "$TARGET" "$FLOOD_PORT" "$PPS" "$FLOOD_SECS" <<'PY' || true
import sys, time, random
from scapy.all import IP, TCP, send
target, port, pps, secs = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
gap = 1.0 / pps
end = time.time() + secs
while time.time() < end:
    src = ".".join(str(random.randint(1, 254)) for _ in range(4))
    send(IP(src=src, dst=target) / TCP(sport=random.randint(1024, 65535),
         dport=port, flags="S"), verbose=0)
    time.sleep(gap)
PY
fi

benign_burst after

echo "== waiting for capture to flush =="
wait "$CAP" 2>/dev/null || true
kill "$WEB" 2>/dev/null || true

ls -lh ddos.pcap
echo
echo "next:"
echo "  ./scripts/run_zeek.sh data/raw/ddos/ddos.pcap data/raw/ddos/zeeklogs"
echo "  python3 src/pipeline.py --logdir data/raw/ddos/zeeklogs --span 30"
