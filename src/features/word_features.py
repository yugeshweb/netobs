#!/usr/bin/env python3
"""Dictionary-segmentation features, aimed at wordlist-style DGA families."""
from functools import lru_cache
from pathlib import Path

DICT_PATHS = ["/usr/share/dict/words", "/usr/share/dict/american-english"]
MIN_WORD = 3
MAX_WORD = 14

WORD_FEATURE_NAMES = [
    "seg_coverage", "seg_words", "seg_longest", "seg_mean_len",
    "seg_fully_covered", "len_vs_quality",
]


@lru_cache(maxsize=1)
def load_words():
    words = set()
    for p in DICT_PATHS:
        f = Path(p)
        if not f.exists():
            continue
        for line in f.read_text(errors="ignore").splitlines():
            w = line.strip().lower()
            if MIN_WORD <= len(w) <= MAX_WORD and w.isalpha():
                words.add(w)
        if words:
            break
    return words


def segment(label, words):
    """Greedy longest-match cover of the label using dictionary words.

    Returns (covered_chars, [word lengths]).
    """
    s = "".join(c for c in label.lower() if c.isalpha())
    n = len(s)
    i = covered = 0
    found = []
    while i < n:
        hit = 0
        for j in range(min(n, i + MAX_WORD), i + MIN_WORD - 1, -1):
            if s[i:j] in words:
                hit = j - i
                break
        if hit:
            found.append(hit)
            covered += hit
            i += hit
        else:
            i += 1
    return covered, found


def word_features(label, trigram_score):
    words = load_words()
    s = "".join(c for c in (label or "").lower() if c.isalpha())
    n = len(s)
    if n == 0 or not words:
        return [0.0] * len(WORD_FEATURE_NAMES)

    covered, found = segment(s, words)
    coverage = covered / n

    # The contradiction that exposes wordlist DGAs: plausible letter
    # statistics paired with an implausible length.
    quality = max(0.0, min(1.0, (trigram_score + 14.0) / 8.0))
    len_vs_quality = quality * (n / 12.0)

    return [
        coverage,
        float(len(found)),
        float(max(found) if found else 0),
        (sum(found) / len(found)) if found else 0.0,
        1.0 if coverage >= 0.95 else 0.0,
        len_vs_quality,
    ]
