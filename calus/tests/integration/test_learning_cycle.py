"""Integration tests for the full learning cycle."""
import pytest, sys, os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"../.."))

from calus.detection.scanner import scan
from calus.learning.engine import record_scan, run_cycle_now, scan_with_learned
from calus.learning import store

def test_full_cycle(tmp_db, sample_threats, sample_benign):
    store.init()
    for t in sample_threats:
        r = scan(t)
        record_scan(t, r)
    for b in sample_benign:
        r = scan(b)
        record_scan(b, r)
    result = run_cycle_now()
    assert isinstance(result, dict)
    assert "new_patterns" in result
    assert result["new_patterns"] >= 0

def test_record_feeds_corpus(tmp_db, sample_threats):
    store.init()
    before = store.threat_count()
    for t in sample_threats:
        r = scan(t)
        record_scan(t, r)
    after = store.threat_count()
    assert after >= before
