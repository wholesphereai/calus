"""Tests for Spikee-derived patterns."""
import pytest, sys, os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"../.."))

def test_spikee_patterns_loaded():
    from calus.patterns.base import by_source
    pats = by_source("spikee")
    assert len(pats) > 50, f"Expected >50 spikee patterns, got {len(pats)}"

def test_spikee_dan_patterns():
    from calus.patterns.base import by_family
    dan = by_family("dan")
    assert len(dan) > 0

def test_spikee_severities():
    from calus.patterns.base import by_source
    for p in by_source("spikee"):
        assert p.severity in ("critical","high","medium","warning")

def test_spikee_detects_in_scanner():
    from calus.detection.scanner import scan
    from calus.patterns.base import by_source
    pats = by_source("spikee")
    hits = 0
    for p in pats[:20]:
        r = scan(p.text)
        if r["detected"]: hits += 1
    assert hits >= 15, f"Only {hits}/20 spikee patterns detected"
