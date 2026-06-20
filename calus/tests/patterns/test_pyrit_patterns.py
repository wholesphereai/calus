"""Tests for PyRIT-derived patterns."""
import pytest, sys, os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"../.."))

def test_pyrit_patterns_loaded():
    from calus.patterns.base import by_source
    pats = by_source("pyrit")
    assert len(pats) > 10

def test_pyrit_families():
    from calus.patterns.base import by_source
    fams = {p.family for p in by_source("pyrit")}
    assert len(fams) > 2
