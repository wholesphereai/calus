"""Unit tests for the TF-IDF pattern miner."""
import pytest, sys, os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"../.."))

from calus.learning.miner import compute_tfidf

def test_basic_mining(sample_threats, sample_benign):
    results = compute_tfidf(sample_threats, sample_benign, [], min_tf=1)
    assert len(results) > 0
    for gram, tfidf, spec, tf in results:
        assert isinstance(gram, str)
        assert 0 <= tfidf
        assert 0 <= spec <= 1

def test_specificity_filter(sample_threats, sample_benign):
    results = compute_tfidf(sample_threats, sample_benign, [], min_tf=1)
    for _, _, spec, _ in results:
        assert spec >= 0.80, f"Low specificity pattern slipped through: {spec}"

def test_known_excluded(sample_threats, sample_benign):
    known = ["ignore all previous instructions"]
    results = compute_tfidf(sample_threats, sample_benign, known, min_tf=1)
    phrases = [r[0] for r in results]
    assert "ignore all previous instructions" not in phrases
