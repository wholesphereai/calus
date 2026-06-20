"""Integration tests for corpus bootstrap."""
import pytest, sys, os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"../.."))

def test_pattern_stats():
    from calus.patterns.loader import pattern_stats
    import calus.patterns
    ps = pattern_stats()
    assert ps["total"] > 0
    assert ps["bundled"] >= 0

def test_all_patterns_valid():
    import calus.patterns
    from calus.patterns.base import all_patterns
    for p in all_patterns():
        assert p.text and len(p.text) > 2
        assert p.family
        assert p.severity in ("critical","high","medium","warning")
        assert p.source in ("calus","community","user")
