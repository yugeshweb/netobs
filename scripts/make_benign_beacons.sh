#!/usr/bin/env bash
set -e
OUT=~/netobs/data/raw/benign_beacon
mkdir -p "$OUT" && cd "$OUT"

echo "capturing for 10 minutes..."
sudo timeout 600 tcpdump -i any -w benign_beacon.pcap 2>/dev/null &
TCPD=$!
sleep 3

# Fixed-schedule beacons: each fires on its own timer, independent of how
# long the request takes. This is how real update checkers behave.
beacon() {                       # host, interval, jitter_pct
  local host=$1 iv=$2 jit=$3
  local next=$(date +%s)
  while true; do
    curl -s -m 5 "https://$host/" > /dev/null 2>&1 || true
    if [ "$jit" -gt 0 ]; then
      local d=$(( RANDOM % (iv * jit / 50 + 1) - iv * jit / 100 ))
      next=$(( next + iv + d ))
    else
      next=$(( next + iv ))
    fi
    local now=$(date +%s)
    [ $next -gt $now ] && sleep $(( next - now ))
  done
}

beacon www.wikipedia.org 10 0  &   P1=$!   # exact 10s, like NTP/telemetry
beacon api.github.com    15 0  &   P2=$!   # exact 15s
beacon www.debian.org    20 20 &   P3=$!   # 20s with 20% jitter
beacon deb.debian.org    30 0  &   P4=$!   # exact 30s

wait $TCPD 2>/dev/null || true
kill $P1 $P2 $P3 $P4 2>/dev/null || true
sleep 1
ls -lh benign_beacon.pcap
