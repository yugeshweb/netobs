#!/usr/bin/env bash
# Pull ssl.log and x509.log from Stratosphere captures. Logs only, no pcaps,
# no malware samples.
BASE="https://mcfp.felk.cvut.cz/publicDatasets"
OUT=~/netobs/data/raw/tls_logs
mkdir -p "$OUT"/{malicious,benign}

get() {                          # capture_dir, class
  local cap=$1 cls=$2
  local d="$OUT/$cls/$cap"
  mkdir -p "$d"
  for f in ssl.log x509.log conn.log; do
    curl -sf --max-time 120 -o "$d/$f" "$BASE/$cap/bro/$f" || rm -f "$d/$f"
  done
  if [ -s "$d/ssl.log" ]; then
    printf "  %-45s ssl=%s lines\n" "$cap" "$(wc -l < "$d/ssl.log")"
  else
    rm -rf "$d"
  fi
}

echo "malicious:"
for n in 348 349 350 351 352 353 354 355 364 367 368 369 370 371 372 373 374 \
         400 402 403 404 405 406 407 408 409 410; do
  for suffix in 1 2 3 4; do
    cap="CTU-Malware-Capture-Botnet-${n}-${suffix}"
    curl -sf --max-time 20 -o /dev/null "$BASE/$cap/" && get "$cap" malicious
  done
done

echo "benign:"
for n in 20 21 22 23 24 25 26 27 28 29 30 31 32; do
  get "CTU-Normal-$n" benign
done

echo
echo "totals:"
echo "  malicious ssl lines: $(cat "$OUT"/malicious/*/ssl.log 2>/dev/null | wc -l)"
echo "  benign    ssl lines: $(cat "$OUT"/benign/*/ssl.log 2>/dev/null | wc -l)"
