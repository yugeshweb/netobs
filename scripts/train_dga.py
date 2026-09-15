#!/usr/bin/env python3
"""Train and evaluate the DGA domain classifier."""
import csv, json, sys
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
from lightgbm import LGBMClassifier
from sklearn.metrics import (classification_report, confusion_matrix,
                             roc_auc_score)
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from features.dns_features import (NgramModel, domain_features, split_domain,
                                   FEATURE_NAMES)
from features.word_features import word_features, WORD_FEATURE_NAMES

ALL_FEATURES = FEATURE_NAMES + WORD_FEATURE_NAMES


def full_features(d, bg, tg):
    base = domain_features(d, bg, tg)
    return base + word_features(split_domain(d)[0], base[12])

DATA = ROOT / "data" / "processed" / "dns_dataset.csv"
OUT = ROOT / "data" / "models"


def main():
    rows = list(csv.DictReader(open(DATA)))
    print(f"loaded {len(rows)} rows: {dict(Counter(r['family'] for r in rows))}\n")

    domains = [r["domain"] for r in rows]
    y = np.array([int(r["label"]) for r in rows])
    fam = [r["family"] for r in rows]

    # Split first, then fit n-grams on training benign only. Fitting on
    # everything would leak test information into the features.
    idx = np.arange(len(rows))
    tr, te = train_test_split(idx, test_size=0.25, random_state=42, stratify=y)

    train_benign = [split_domain(domains[i])[0] for i in tr if y[i] == 0]
    bg = NgramModel(2).fit(train_benign)
    tg = NgramModel(3).fit(train_benign)

    X = np.array([full_features(d, bg, tg) for d in domains], dtype=float)
    Xtr, Xte, ytr, yte = X[tr], X[te], y[tr], y[te]

    clf = LGBMClassifier(n_estimators=300, learning_rate=0.08, num_leaves=48,
                         subsample=0.9, colsample_bytree=0.9,
                         random_state=42, verbose=-1)
    clf.fit(Xtr, ytr)

    prob = clf.predict_proba(Xte)[:, 1]
    pred = (prob >= 0.5).astype(int)

    print(classification_report(yte, pred, target_names=["benign", "dga"], digits=4))
    print("confusion matrix [rows=true, cols=pred]:")
    print(confusion_matrix(yte, pred), "\n")
    print(f"ROC AUC: {roc_auc_score(yte, prob):.4f}\n")

    print("recall by family:")
    for f in sorted(set(fam)):
        mask = np.array([fam[i] == f for i in te])
        if mask.sum() == 0:
            continue
        sub_true, sub_pred = yte[mask], pred[mask]
        acc = (sub_true == sub_pred).mean()
        print(f"  {f:14s} n={mask.sum():6d}  correct={acc:.4f}")

    print("\nfeature importance:")
    for name, imp in sorted(zip(ALL_FEATURES, clf.feature_importances_),
                            key=lambda kv: -kv[1]):
        print(f"  {name:16s} {imp}")

    OUT.mkdir(parents=True, exist_ok=True)
    joblib.dump({"clf": clf, "bigrams": bg, "trigrams": tg,
                 "features": ALL_FEATURES}, OUT / "dga_model.joblib")
    print(f"\nsaved to {OUT / 'dga_model.joblib'}")


if __name__ == "__main__":
    main()
