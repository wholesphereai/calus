"""
CALUS.learning.evolver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Clusters similar n-gram candidates and generalises them into regex patterns.

Algorithm:
  1. Jaccard similarity clustering (word sets, threshold configurable)
  2. Per-cluster: find fixed words + variable positions
  3. Generate regex:  fixed[space]+words[space]+(var1|var2|var3)  anchored to word boundaries
  4. Score the generated regex against threat/benign corpora
  5. Return EvolvedPattern objects

Example:
  Cluster:
    "ignore all previous instructions"
    "ignore all prior instructions"
    "ignore all your instructions"
  → regex:  ignore[s]+all[s]+(previous|prior|your)[s]+instructions  (word-boundary anchored)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple


@dataclass
class EvolvedPattern:
    phrase: str            # canonical human-readable form
    regex: str             # compiled-ready regex string
    attack_family: str
    source_ngrams: List[str]
    score: float = 0.0
    precision: float = 0.0
    specificity: float = 0.0
    coverage: int = 0


def _word_set(phrase: str) -> Set[str]:
    return set(phrase.split())


def _jaccard(a: str, b: str) -> float:
    sa, sb = _word_set(a), _word_set(b)
    inter = len(sa & sb)
    union = len(sa | sb)
    return inter / union if union else 0.0


def _longest_common_words(phrases: List[str]) -> List[str]:
    """Find words that appear in ALL phrases (order-preserving from first phrase)."""
    if not phrases:
        return []
    word_sets = [set(p.split()) for p in phrases]
    common = word_sets[0]
    for s in word_sets[1:]:
        common &= s
    # Keep order from first phrase
    return [w for w in phrases[0].split() if w in common]


def _variable_words_at_pos(phrases: List[str], pos: int) -> List[str]:
    """Get unique words at position pos across all phrases."""
    words = []
    for p in phrases:
        toks = p.split()
        if pos < len(toks):
            words.append(toks[pos])
    return list(dict.fromkeys(words))  # unique, order-preserving


def _make_regex(phrases: List[str]) -> Tuple[str, str]:
    """
    Build a regex and canonical phrase from a cluster of similar phrases.
    Returns (phrase, regex).
    """
    if len(phrases) == 1:
        phrase = phrases[0]
        escaped = re.escape(phrase)
        regex = r'\b' + re.sub(r'\\ ', r'\\s+', escaped) + r'\b'
        return phrase, regex

    # Align all phrases to same length by trimming to min-length token count
    all_tokens = [p.split() for p in phrases]
    min_len = min(len(t) for t in all_tokens)
    all_tokens = [t[:min_len] for t in all_tokens]

    parts = []
    for i in range(min_len):
        col = [t[i] for t in all_tokens]
        unique = list(dict.fromkeys(col))
        if len(unique) == 1:
            parts.append(re.escape(unique[0]))
        else:
            # Build alternation, capped at 8 variants
            alts = [re.escape(w) for w in unique[:8]]
            parts.append(f"({'|'.join(alts)})")

    regex  = r'\b' + r'\s+'.join(parts) + r'\b'
    phrase = ' '.join(all_tokens[0])  # use first phrase as canonical
    return phrase, regex


def cluster(
    candidates: List[str],
    similarity_threshold: float = 0.55,
) -> List[List[str]]:
    """
    Greedy Jaccard-similarity clustering.
    Returns list of clusters (each cluster is a list of phrases).
    """
    clusters: List[List[str]] = []
    used = [False] * len(candidates)

    for i, cand in enumerate(candidates):
        if used[i]:
            continue
        cluster_members = [cand]
        used[i] = True
        for j in range(i + 1, len(candidates)):
            if used[j]:
                continue
            if _jaccard(cand, candidates[j]) >= similarity_threshold:
                cluster_members.append(candidates[j])
                used[j] = True
        clusters.append(cluster_members)

    return clusters


def score_pattern(
    regex: str,
    threat_texts: List[str],
    benign_texts: List[str],
) -> Tuple[float, float, float, int]:
    """
    Score a regex pattern against corpora.
    Returns (composite_score, precision, specificity, coverage).
    """
    try:
        pat = re.compile(regex, re.IGNORECASE)
    except re.error:
        return 0.0, 0.0, 0.0, 0

    threat_hits  = sum(1 for t in threat_texts if pat.search(t))
    benign_hits  = sum(1 for t in benign_texts if pat.search(t))

    total_hits = threat_hits + benign_hits
    precision   = threat_hits / total_hits if total_hits > 0 else 0.0
    coverage    = threat_hits
    n_benign    = max(len(benign_texts), 1)
    specificity = 1.0 - (benign_hits / n_benign)

    # Composite score
    composite = 0.5 * precision + 0.3 * specificity + 0.2 * min(coverage / 10, 1.0)
    return round(composite, 4), round(precision, 4), round(specificity, 4), coverage


def evolve(
    candidates: List[str],
    threat_texts: List[str],
    benign_texts: List[str],
    attack_family: str = "learned",
    min_score: float = 0.65,
    min_coverage: int = 2,
    similarity_threshold: float = 0.55,
) -> List[EvolvedPattern]:
    """
    Full evolution pipeline: cluster → generalise → score → filter.
    Returns EvolvedPattern list ordered by score descending.
    """
    if not candidates or not threat_texts:
        return []

    clusters_list = cluster(candidates, similarity_threshold)
    results: List[EvolvedPattern] = []

    for cluster_members in clusters_list:
        phrase, regex = _make_regex(cluster_members)

        try:
            re.compile(regex)
        except re.error:
            # Bad regex — fall back to escaped literal
            phrase  = cluster_members[0]
            regex   = r'\b' + re.sub(r'\\ ', r'\\s+', re.escape(phrase)) + r'\b'

        score, precision, specificity, coverage = score_pattern(
            regex, threat_texts, benign_texts
        )

        if score < min_score:
            continue
        if coverage < min_coverage:
            continue
        if precision < 0.6:
            continue

        results.append(EvolvedPattern(
            phrase=phrase,
            regex=regex,
            attack_family=attack_family,
            source_ngrams=cluster_members,
            score=score,
            precision=precision,
            specificity=specificity,
            coverage=coverage,
        ))

    results.sort(key=lambda p: p.score, reverse=True)
    return results
