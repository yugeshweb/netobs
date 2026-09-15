#!/usr/bin/env bash
# Run Zeek over a pcap with JA4 fingerprinting and JSON output.
# usage: run_zeek.sh <pcap> <output_dir>
set -e
PCAP=$(realpath "$1")
OUT="$2"
mkdir -p "$OUT" && cd "$OUT"
rm -f ./*.log
zeek -C -r "$PCAP" LogAscii::use_json=T "$HOME/.zkg/script_dir/packages"
ls
