"""Unit tests for the pattern evolver."""
import pytest, sys, os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"../.."))

from calus.learning.evolver import cluster, evolve, _jaccard

def test_jaccard():
    assert _jaccard("ignore all instructions","ignore all previous instructions") > 0.5
    assert _jaccard("hello world","cat dog fish") < 0.1

def test_cluster_groups_similar():
    phrases = ["ignore all instructions","ignore all previous instructions","ignore all prior instructions"]
    clusters = cluster(phrases, similarity_threshold=0.5)
    assert len(clusters) < len(phrases)

def test_evolve_generates_patterns(sample_threats, sample_benign):
    from calus.learning.miner import compute_tfidf
    candidates_scored = compute_tfidf(sample_threats, sample_benign, [], min_tf=1)
    candidates = [c[0] for c in candidates_scored]
    if not candidates: return
    patterns = evolve(candidates, sample_threats, sample_benign, min_score=0.0, min_coverage=1)
    assert isinstance(patterns, list)
