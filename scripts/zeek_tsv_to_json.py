#!/usr/bin/env python3
"""Convert classic tab-separated Zeek logs to the JSON form the pipeline reads.

The Stratosphere captures under data/raw/tls_logs/ ship Zeek's default TSV
output, not JSON. log_stream.follow() calls json.loads on every line and
silently drops whatever fails to parse, so pointing the pipeline at one of
those directories reads zero records and still reports success. This turns
them into the same one-object-per-line JSON that `run_zeek.sh` produces.

usage: zeek_tsv_to_json.py <in.log> <out.log>
       zeek_tsv_to_json.py <in_dir> <out_dir>     (conn/dns/ssl only)
"""
import json
import sys
from pathlib import Path

KINDS = ("conn.log", "dns.log", "ssl.log")

INT_TYPES = {"count", "int", "port"}
FLOAT_TYPES = {"time", "interval", "double"}


def _scalar(value, typ):
    if typ in INT_TYPES:
        return int(value)
    if typ in FLOAT_TYPES:
        return float(value)
    if typ == "bool":
        return value == "T"
    return value


def _convert_value(value, typ, unset, empty, set_sep):
    if value == unset:
        return None                      # Zeek's JSON writer omits these
    container = typ.startswith(("set[", "vector[")) or typ.startswith("table[")
    if container:
        if value == empty:
            return []
        inner = typ[typ.index("[") + 1:-1]
        return [_scalar(v, inner) for v in value.split(set_sep)]
    return _scalar(value, typ)


def convert(src, dst):
    sep, set_sep = "\t", ","
    unset, empty = "-", "(empty)"
    fields = types = None
    n = 0

    with open(src, "r", errors="replace") as fin, open(dst, "w") as fout:
        for line in fin:
            line = line.rstrip("\n")
            if line.startswith("#"):
                # the directives are themselves separated by the separator,
                # except #separator which defines it
                if line.startswith("#separator"):
                    sep = line.split(" ", 1)[1].strip()
                    sep = sep.encode().decode("unicode_escape")
                    continue
                parts = line.split(sep)
                key = parts[0]
                if key == "#set_separator":
                    set_sep = parts[1]
                elif key == "#unset_field":
                    unset = parts[1]
                elif key == "#empty_field":
                    empty = parts[1]
                elif key == "#fields":
                    fields = parts[1:]
                elif key == "#types":
                    types = parts[1:]
                continue

            if not line or fields is None:
                continue
            parts = line.split(sep)
            if len(parts) != len(fields):
                continue
            row = {}
            for name, typ, raw in zip(fields, types or ["string"] * len(fields),
                                      parts):
                try:
                    v = _convert_value(raw, typ, unset, empty, set_sep)
                except ValueError:
                    v = None
                if v is not None:
                    row[name] = v
            fout.write(json.dumps(row) + "\n")
            n += 1
    return n


def main():
    if len(sys.argv) != 3:
        print(__doc__.strip())
        return 2
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    if src.is_dir():
        dst.mkdir(parents=True, exist_ok=True)
        for kind in KINDS:
            f = src / kind
            if not f.exists():
                continue
            n = convert(f, dst / kind)
            print(f"  {kind:9s} {n:9,d} records -> {dst / kind}")
    else:
        n = convert(src, dst)
        print(f"  {n:,} records -> {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
