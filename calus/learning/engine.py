"""
CALUS.learning.engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Self-Improvement Engine — orchestrates the full learning loop.

Flow:
  1. Every scan feeds the corpora (threat_corpus / benign_corpus)
  2. Every N new threats, a learning cycle runs automatically
  3. Learning cycle: normalize → mine → evolve → score → propose
  4. Accepted patterns load into Aho-Corasick for instant future detection
  5. False positives prune bad patterns automatically

Called by the interceptor on every scan.
CLI: `CALUS learn` to review/accept proposals.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from typing import List

from calus.learning import store
from calus.learning.normalizer import normalize, all_ngrams
from calus.learning.miner import compute_tfidf
from calus.learning.evolver import evolve, EvolvedPattern

log = logging.getLogger(__name__)

# How many new threats trigger an auto learning cycle
AUTO_LEARN_EVERY = 10
_threat_since_last_cycle = 0
_cycle_lock = threading.Lock()


# ── Public API called by scanner/interceptor ──────────────────────────────────

def record_scan(raw_text: str, scan_result: dict,
                graph: str = None, node: str = None) -> None:
    """
    Record every scan result.
    - Threats → threat_corpus + maybe trigger learning cycle
    - Clean   → benign_corpus (sampled)
    """
    global _threat_since_last_cycle

    norm = normalize(raw_text)
    if not norm:
        return

    detected = scan_result.get("detected", False)
    severity = scan_result.get("severity", "none")

    if detected:
        layers = [
            k for k, v in scan_result.get("layers", {}).items()
            if isinstance(v, dict) and v.get("detected")
        ]
        store.add_threat(raw_text[:2000], norm[:2000], severity, layers, graph, node)

        with _cycle_lock:
            _threat_since_last_cycle += 1
            should_run = _threat_since_last_cycle >= AUTO_LEARN_EVERY

        if should_run:
            with _cycle_lock:
                _threat_since_last_cycle = 0
            # Run in background thread — never blocks scanning
            t = threading.Thread(target=_run_cycle, daemon=True)
            t.start()
    else:
        # Sample 1-in-3 clean messages for benign corpus
        import random
        if random.random() < 0.33:
            store.add_benign(norm[:2000])


def record_fp(pattern_text: str, text_sample: str = None) -> None:
    """Report a false positive for a learned pattern."""
    with store._conn() as c:
        row = c.execute(
            "SELECT id FROM learned_patterns WHERE pattern_text=?",
            (pattern_text,)
        ).fetchone()
    if row:
        store.report_fp(row["id"], text_sample)


# ── Learning cycle ────────────────────────────────────────────────────────────

def _run_cycle() -> None:
    """
    Full learning cycle — runs in background thread.
    Mine → Evolve → Score → Propose patterns.
    """
    t0 = time.perf_counter()
    try:
        threats = store.threat_sample(limit=1500)
        benign  = store.benign_sample(limit=1500)

        if len(threats) < 5:
            log.debug("[CALUS:engine] not enough threats yet (%d)", len(threats))
            return

        # Load known static phrases so we don't re-learn them
        from calus.detection.signatures import DIRECT_PHRASES
        known = list(DIRECT_PHRASES)

        # Also load already-accepted learned patterns
        active = [p["pattern_text"] for p in store.load_active_patterns()]
        known += active

        # Mine candidates
        candidates_scored = compute_tfidf(
            threats, benign, known,
            min_n=2, max_n=6,
            min_tf=2,
            top_k=300,
        )

        if not candidates_scored:
            log.debug("[CALUS:engine] no candidates from mining")
            return

        candidate_phrases = [c[0] for c in candidates_scored]

        # Evolve into patterns
        patterns = evolve(
            candidate_phrases,
            threats,
            benign,
            attack_family="learned",
            min_score=0.65,
            min_coverage=2,
        )

        new_count = 0
        for p in patterns:
            pid = store.upsert_pattern(
                pattern_text=p.phrase,
                pattern_regex=p.regex,
                attack_family=p.attack_family,
                score=p.score,
                precision=p.precision_score if hasattr(p, 'precision_score') else p.precision,
                specificity=p.specificity,
                coverage=p.coverage,
                source_count=len(p.source_ngrams),
            )
            new_count += 1

        elapsed = (time.perf_counter() - t0) * 1000
        log.info(
            "[CALUS:engine] cycle done: %d threats, %d candidates → %d patterns (%.0fms)",
            len(threats), len(candidate_phrases), new_count, elapsed,
        )

        # Auto-accept very high confidence patterns (score ≥ 0.90)
        pending = store.pending_patterns(min_score=0.90)
        auto_accepted = 0
        for p in pending:
            store.accept(p["id"])
            auto_accepted += 1
            reload_learned_patterns()

        if auto_accepted:
            log.info("[CALUS:engine] auto-accepted %d high-confidence patterns", auto_accepted)

    except Exception as exc:
        log.warning("[CALUS:engine] cycle failed: %s", exc)


# ── Runtime pattern loading ───────────────────────────────────────────────────

_learned_cache: list = []
_cache_lock = threading.Lock()
_cache_ts: float = 0.0
_CACHE_TTL = 30.0  # reload every 30 seconds


def get_learned_patterns() -> list:
    """
    Return accepted learned patterns as list of (phrase, regex, family, id).
    Cached with 30s TTL.
    """
    global _learned_cache, _cache_ts
    now = time.time()
    with _cache_lock:
        if now - _cache_ts > _CACHE_TTL:
            try:
                rows = store.load_active_patterns()
                _learned_cache = [
                    (r["pattern_text"], r["pattern_regex"],
                     r["attack_family"], r["id"])
                    for r in rows
                ]
                _cache_ts = now
            except Exception as exc:
                log.debug("[CALUS:engine] pattern reload failed: %s", exc)
        return list(_learned_cache)


def reload_learned_patterns() -> None:
    """Force reload of the pattern cache."""
    global _cache_ts
    with _cache_lock:
        _cache_ts = 0.0


def scan_with_learned(text: str) -> dict:
    """
    Scan text against all accepted learned patterns.
    Returns dict with detected/severity/hits.
    """
    norm = normalize(text)
    patterns = get_learned_patterns()

    hits = []
    for phrase, regex, family, pid in patterns:
        try:
            if re.search(regex, norm, re.IGNORECASE):
                hits.append({
                    "pattern_text": phrase,
                    "pattern_regex": regex,
                    "attack_family": family,
                    "pattern_id": pid,
                })
                store.record_hit(pid)
        except re.error:
            # Regex compiled at generation time but double-check
            if phrase in norm:
                hits.append({
                    "pattern_text": phrase,
                    "pattern_regex": phrase,
                    "attack_family": family,
                    "pattern_id": pid,
                })
                store.record_hit(pid)

    detected = len(hits) > 0
    return {
        "detected": detected,
        "severity": "high" if detected else "none",
        "layer":    "learned",
        "hits":     hits,
    }


def run_cycle_now() -> dict:
    """
    Manually trigger a learning cycle and return stats.
    Called by `CALUS learn --run`.
    """
    t0 = time.perf_counter()
    before = store.stats()
    _run_cycle()
    after  = store.stats()
    elapsed = (time.perf_counter() - t0) * 1000
    return {
        "elapsed_ms":    round(elapsed),
        "threats_in_db": after["threat_corpus"],
        "benign_in_db":  after["benign_corpus"],
        "new_patterns":  after["patterns_total"] - before["patterns_total"],
        "pending":       after["pending"],
        "accepted":      after["accepted"],
    }
