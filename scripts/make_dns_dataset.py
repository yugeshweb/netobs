#!/usr/bin/env python3
"""Build the DNS training set: benign domains (Tranco) + synthetic DGA domains."""
import csv, hashlib, io, random, string, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "processed" / "dns_dataset.csv"
N = 50000
random.seed(42)

TLDS = [".com", ".net", ".org", ".info", ".biz", ".ru", ".cc", ".top", ".xyz"]
WORDS = """time year people way day man thing woman life child world school state
family student group country problem hand part place case week company system
program question work government number night point home water room mother area
money story fact month lot right study book eye job word business issue side kind
head house service friend father power hour game line member car city name team
minute idea body information back parent face level office door health person art
war history party result change morning reason research girl guy moment air teacher
force education""".split()

def benign(n):
    out = []
    with zipfile.ZipFile(RAW / "tranco-top1m.csv.zip") as zf:
        with zf.open(zf.namelist()[0]) as f:
            for line in io.TextIOWrapper(f, "utf-8"):
                parts = line.strip().split(",")
                if len(parts) == 2:
                    out.append(parts[1])
                if len(out) >= n:
                    break
    return out

def dga_random(n):
    chars = string.ascii_lowercase + string.digits
    return [("".join(random.choice(chars) for _ in range(random.randint(8, 20)))
             + random.choice(TLDS)) for _ in range(n)]

def dga_hash(n):
    out = []
    for i in range(n):
        seed = f"{random.randint(0, 10**9)}-{i}"
        h = hashlib.md5(seed.encode()).hexdigest()
        out.append(h[:random.randint(12, 18)] + random.choice(TLDS))
    return out

def dga_wordlist(n):
    out = []
    for _ in range(n):
        d = "".join(random.choice(WORDS) for _ in range(random.randint(2, 3)))
        if random.random() < 0.4:
            d += str(random.randint(10, 9999))
        out.append(d + random.choice(TLDS))
    return out

def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    rows = [(d, 0, "benign") for d in benign(N)]
    per = N // 3
    rows += [(d, 1, "dga_random") for d in dga_random(per)]
    rows += [(d, 1, "dga_hash") for d in dga_hash(per)]
    rows += [(d, 1, "dga_wordlist") for d in dga_wordlist(N - 2 * per)]
    random.shuffle(rows)
    with open(OUT, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["domain", "label", "family"])
        w.writerows(rows)
    print(f"wrote {len(rows)} rows to {OUT}")
    for fam in ("benign", "dga_random", "dga_hash", "dga_wordlist"):
        sample = [r[0] for r in rows if r[2] == fam][:3]
        print(f"  {fam:14s} {sample}")

if __name__ == "__main__":
    main()
