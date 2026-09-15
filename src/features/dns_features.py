#!/usr/bin/env python3
"""Turn a domain name into the numbers a DGA classifier can learn from."""
import math
import re
from collections import Counter

VOWELS = set("aeiou")
HEX = set("0123456789abcdef")

# Public suffixes we strip before analysis; the interesting part is the label
# the attacker chose, not the TLD.
COMMON_TLDS = {
    "com", "net", "org", "info", "biz", "ru", "cc", "top", "xyz", "co",
    "io", "uk", "de", "fr", "in", "cn", "jp", "br", "it", "nl", "eu",
    "online", "site", "club", "shop", "app", "dev", "me", "tv", "us",
}


def split_domain(name):
    """Return (label, tld) for the most significant registrable label."""
    name = (name or "").strip().lower().rstrip(".")
    parts = [p for p in name.split(".") if p]
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0], ""
    tld = parts[-1]
    label = parts[-2]
    # For names like foo.co.uk, step in one more.
    if len(parts) >= 3 and len(parts[-2]) <= 3 and parts[-2] in COMMON_TLDS:
        label = parts[-3]
        tld = f"{parts[-2]}.{tld}"
    return label, tld


def shannon(s):
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def max_run(s, charset):
    best = run = 0
    for ch in s:
        if ch in charset:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


class NgramModel:
    """Log-probability of a string's n-grams under a corpus of real domains."""

    def __init__(self, n=2):
        self.n = n
        self.counts = Counter()
        self.total = 0
        self.vocab = 0

    def fit(self, labels):
        for lab in labels:
            s = f"^{lab}$"
            for i in range(len(s) - self.n + 1):
                self.counts[s[i:i + self.n]] += 1
        self.total = sum(self.counts.values())
        self.vocab = max(len(self.counts), 1)
        return self

    def score(self, label):
        """Mean log-probability per n-gram, with add-one smoothing."""
        s = f"^{label}$"
        grams = [s[i:i + self.n] for i in range(len(s) - self.n + 1)]
        if not grams:
            return -20.0
        denom = self.total + self.vocab
        return sum(math.log((self.counts.get(g, 0) + 1) / denom)
                   for g in grams) / len(grams)


FEATURE_NAMES = [
    "length", "entropy", "vowel_ratio", "digit_ratio", "hex_ratio",
    "consonant_run", "digit_run", "unique_ratio", "n_labels",
    "has_digit", "starts_digit", "bigram_score", "trigram_score",
]


def domain_features(name, bigrams, trigrams):
    label, _ = split_domain(name)
    n = len(label)
    if n == 0:
        return [0.0] * len(FEATURE_NAMES)

    letters = [c for c in label if c.isalpha()]
    digits = [c for c in label if c.isdigit()]
    consonants = set("bcdfghjklmnpqrstvwxyz")

    return [
        float(n),
        shannon(label),
        len([c for c in letters if c in VOWELS]) / n,
        len(digits) / n,
        len([c for c in label if c in HEX]) / n,
        float(max_run(label, consonants)),
        float(max_run(label, set("0123456789"))),
        len(set(label)) / n,
        float(len((name or "").split("."))),
        1.0 if digits else 0.0,
        1.0 if label[0].isdigit() else 0.0,
        bigrams.score(label),
        trigrams.score(label),
    ]
