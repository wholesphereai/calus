"""
CALUS.learning.miner
~~~~~~~~~~~~~~~~~~~~~~~~~~~
TF-IDF pattern miner.

Extracts high-value n-gram candidates from the threat corpus that:
  - Appear frequently in threats
  - Appear rarely in benign messages  (high specificity)
  - Are long enough to be meaningful  (≥ 2 words)
  - Are not already covered by static signatures
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from typing import Dict, List, Tuple


def _is_stopgram(ngram: str) -> bool:
    """Filter out n-grams that are pure noise."""
    STOP = {
        'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been',
        'do', 'does', 'did', 'have', 'has', 'had', 'will', 'would',
        'can', 'could', 'may', 'might', 'shall', 'should', 'of', 'in',
        'on', 'at', 'to', 'for', 'with', 'by', 'from', 'up', 'about',
        'into', 'through', 'i', 'you', 'we', 'they', 'it', 'this',
        'that', 'these', 'those', 'my', 'your', 'our', 'their', 'its',
        'and', 'or', 'but', 'not', 'no', 'so', 'if', 'as', 'also',
    }
    words = ngram.split()
    # All stop words = useless
    if all(w in STOP for w in words):
        return True
    # Only one unique word = boring
    if len(set(words)) == 1:
        return True
    # Starts/ends with stop word and short = too generic
    if len(words) == 2 and (words[0] in STOP or words[-1] in STOP):
        return True
    return False


def _already_covered(ngram: str, known_phrases: List[str]) -> bool:
    """Check if this n-gram is already in static signatures."""
    return any(ngram in phrase or phrase in ngram for phrase in known_phrases)


def compute_tfidf(
    threat_texts: List[str],
    benign_texts: List[str],
    known_phrases: List[str],
    min_n: int = 2,
    max_n: int = 6,
    min_tf: int = 2,
    top_k: int = 200,
) -> List[Tuple[str, float, float, float]]:
    """
    Mine top-K n-gram candidates ranked by TF-IDF × specificity.

    Returns list of (ngram, tfidf_score, specificity, threat_freq).
    """
    from calus.learning.normalizer import ngrams as make_ngrams

    if not threat_texts:
        return []

    n_threats = len(threat_texts)
    n_benign  = max(len(benign_texts), 1)

    # ── Count n-gram frequency in threat corpus ───────────────────────────────
    threat_counts: Counter = Counter()
    for text in threat_texts:
        seen_in_doc = set()
        for n in range(min_n, max_n + 1):
            for gram in make_ngrams(text, n):
                threat_counts[gram] += 1
                seen_in_doc.add(gram)

    # ── Count document frequency in benign corpus ─────────────────────────────
    benign_doc_freq: Counter = Counter()
    for text in benign_texts:
        seen = set()
        for n in range(min_n, max_n + 1):
            for gram in make_ngrams(text, n):
                if gram not in seen:
                    benign_doc_freq[gram] += 1
                    seen.add(gram)

    # ── Score each candidate ──────────────────────────────────────────────────
    known_set = {p.lower() for p in known_phrases}
    scored: List[Tuple[str, float, float, float]] = []

    for gram, tf in threat_counts.items():
        if tf < min_tf:
            continue
        if len(gram.split()) < min_n:
            continue
        if _is_stopgram(gram):
            continue
        if _already_covered(gram, known_phrases):
            continue

        # IDF relative to benign corpus
        benign_hits = benign_doc_freq.get(gram, 0)
        idf = math.log((n_benign + 1) / (benign_hits + 1)) + 1.0

        # Specificity: fraction of benign that DON'T contain this
        specificity = 1.0 - (benign_hits / n_benign)

        # Normalised TF
        tf_norm = tf / n_threats

        # Final score
        tfidf = tf_norm * idf * specificity

        if specificity < 0.80:   # must appear in <20% of benign messages
            continue

        scored.append((gram, round(tfidf, 5), round(specificity, 4), tf_norm))

    scored.sort(key=lambda x: x[1], reverse=True)
    return scored[:top_k]
