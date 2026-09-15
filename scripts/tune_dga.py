#!/usr/bin/env python3
"""Measure precision/recall across thresholds and pick an operating point."""
import csv, sys
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from features.dns_features import NgramModel, domain_features, split_domain
from features.word_features import word_features

DATA = ROOT / "data" / "processed" / "dns_dataset.csv"
MODEL = ROOT / "data" / "models" / "dga_model.joblib"

# Rough daily DNS volume for a mid-size network, used to translate a
# false-positive rate into alerts a human would actually have to read.
DAILY_LOOKUPS = 2_000_000
DGA_SHARE = 0.0005


def main():
    bundle = joblib.load(MODEL)
    clf = bundle["clf"]

    rows = list(csv.DictReader(open(DATA)))
    domains = [r["domain"] for r in rows]
    y = np.array([int(r["label"]) for r in rows])
    fam = [r["family"] for r in rows]

    idx = np.arange(len(rows))
    tr, te = train_test_split(idx, test_size=0.25, random_state=42, stratify=y)
    train_benign = [split_domain(domains[i])[0] for i in tr if y[i] == 0]
    bg = NgramModel(2).fit(train_benign)
    tg = NgramModel(3).fit(train_benign)

    def feats(d):
        base = domain_features(d, bg, tg)
        return base + word_features(split_domain(d)[0], base[12])

    Xte = np.array([feats(domains[i]) for i in te], dtype=float)
    yte = y[te]
    famte = [fam[i] for i in te]
    prob = clf.predict_proba(Xte)[:, 1]

    benign_n = int((yte == 0).sum())

    print(f"{'thresh':>7}{'precision':>11}{'recall':>9}{'FP':>7}{'FPR':>9}"
          f"{'wordlist':>10}{'est. FP/day':>13}")
    print("-" * 66)

    rows_out = []
    for t in [0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95]:
        pred = (prob >= t).astype(int)
        tp = int(((pred == 1) & (yte == 1)).sum())
        fp = int(((pred == 1) & (yte == 0)).sum())
        fn = int(((pred == 0) & (yte == 1)).sum())
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / benign_n if benign_n else 0.0

        wl = np.array([f == "dga_wordlist" for f in famte])
        wl_rec = float((pred[wl] == 1).mean()) if wl.sum() else 0.0

        est_fp = fpr * DAILY_LOOKUPS * (1 - DGA_SHARE)
        rows_out.append((t, prec, rec, fp, fpr, wl_rec, est_fp))
        print(f"{t:>7.2f}{prec:>11.4f}{rec:>9.4f}{fp:>7}{fpr:>9.4f}"
              f"{wl_rec:>10.4f}{est_fp:>13,.0f}")

    print("\nNote: est. FP/day assumes ~2M lookups/day and that DGA traffic is")
    print("rare. It is an illustration of alert load, not a measured figure.")


if __name__ == "__main__":
    main()
