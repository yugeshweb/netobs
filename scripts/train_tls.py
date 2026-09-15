#!/usr/bin/env python3
"""Train the encrypted-session classifier on TLS metadata.

Split is by capture, not by row: the test set contains malware families and
benign captures the model never saw, which measures generalisation rather
than memorisation.
"""
import glob, sys
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
from lightgbm import LGBMClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from features.tls_features import tls_features, TLS_FEATURE_NAMES

LOGS = ROOT / "data" / "raw" / "tls_logs"
OUT = ROOT / "data" / "models"


def read_ssl(path):
    fields = None
    for line in open(path, errors="replace"):
        if line.startswith("#fields"):
            fields = line.rstrip("\n").split("\t")[1:]
            continue
        if line.startswith("#") or not line.strip() or not fields:
            continue
        parts = line.rstrip("\n").split("\t")
        if len(parts) != len(fields):
            continue
        yield dict(zip(fields, parts))


def load():
    X, y, groups = [], [], []
    for cls, label in (("benign", 0), ("malicious", 1)):
        for p in sorted(glob.glob(str(LOGS / cls / "*" / "ssl.log"))):
            cap = Path(p).parent.name
            for rec in read_ssl(p):
                X.append(tls_features(rec))
                y.append(label)
                groups.append(cap)
    return np.array(X, dtype=float), np.array(y), np.array(groups)


def main():
    X, y, groups = load()
    caps = sorted(set(groups))
    print(f"{len(X)} sessions from {len(caps)} captures")
    print(f"  benign={int((y==0).sum())} malicious={int((y==1).sum())}\n")

    # Hold out captures by size, not position: tiny captures make a
    # meaningless test set. Keep roughly a third of each class's sessions.
    from collections import Counter
    sizes = Counter(groups)
    ben = sorted([c for c in caps if c.startswith("CTU-Normal")],
                 key=lambda c: -sizes[c])
    mal = sorted([c for c in caps if not c.startswith("CTU-Normal")],
                 key=lambda c: -sizes[c])

    def pick(names, share=0.33):
        total = sum(sizes[c] for c in names)
        want, got, out = total * share, 0, []
        for c in names[1::2]:          # skip the largest, take alternates
            out.append(c); got += sizes[c]
            if got >= want:
                break
        return out

    test_caps = set(pick(ben) + pick(mal))
    print("capture sizes:", {c: sizes[c] for c in mal})
    print("held-out captures:", sorted(test_caps), "\n")

    te = np.isin(groups, list(test_caps))
    tr = ~te
    if te.sum() == 0 or tr.sum() == 0:
        print("split failed"); return

    clf = LGBMClassifier(n_estimators=400, learning_rate=0.05, num_leaves=40,
                         subsample=0.9, colsample_bytree=0.9,
                         random_state=42, verbose=-1)
    clf.fit(X[tr], y[tr])

    prob = clf.predict_proba(X[te])[:, 1]
    pred = (prob >= 0.5).astype(int)

    print(f"train: {int(tr.sum())} sessions, test: {int(te.sum())} sessions\n")
    print(classification_report(y[te], pred, target_names=["benign","malicious"], digits=4))
    print("confusion [rows=true, cols=pred]:")
    print(confusion_matrix(y[te], pred), "\n")
    print(f"ROC AUC: {roc_auc_score(y[te], prob):.4f}\n")

    print("per held-out capture:")
    for c in sorted(test_caps):
        m = groups[te] == c
        if m.sum() == 0:
            continue
        acc = (pred[m] == y[te][m]).mean()
        print(f"  {c:42s} n={m.sum():6d} acc={acc:.4f}")

    print("\nfeature importance (top 12):")
    for n_, i_ in sorted(zip(TLS_FEATURE_NAMES, clf.feature_importances_),
                         key=lambda kv: -kv[1])[:12]:
        print(f"  {n_:20s} {i_}")

    OUT.mkdir(parents=True, exist_ok=True)
    joblib.dump({"clf": clf, "features": TLS_FEATURE_NAMES}, OUT / "tls_model.joblib")
    print(f"\nsaved to {OUT/'tls_model.joblib'}")


if __name__ == "__main__":
    main()
