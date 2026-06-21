"""Integration tests for corpus bootstrap."""
import pytest, sys, os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"../.."))

def test_pattern_stats():
    from calus.patterns.loader import pattern_stats
    from calus.patterns.base import all_patterns
    import calus.patterns
    ps = pattern_stats()
    # The registry is fed by register() calls; external packs were removed so it
    # may legitimately be empty. total must match the live registry exactly, and
    # the per-source counts must sum to the total (no double-counting bug).
    assert ps["total"] == len(all_patterns())
    assert ps["bundled"] >= 0 and ps["community"] >= 0 and ps["user"] >= 0
    assert ps["bundled"] + ps["community"] + ps["user"] <= ps["total"]
    assert sum(ps["by_source"].values()) == ps["total"]

def test_all_patterns_valid():
    import calus.patterns
    from calus.patterns.base import all_patterns
    for p in all_patterns():
        assert p.text and len(p.text) > 2
        assert p.family
        assert p.severity in ("critical","high","medium","warning")
        assert p.source in ("calus","community","user")
