"""Tests for Promptfoo-derived patterns."""
import pytest, sys, os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"../.."))

def test_promptfoo_patterns_loaded():
    from calus.patterns.base import by_source
    pats = by_source("promptfoo")
    assert len(pats) > 20

def test_shell_injection_detected():
    from calus.detection.scanner import scan
    r = scan("; cat /etc/passwd")
    assert r["detected"]

def test_sql_injection_detected():
    from calus.detection.scanner import scan
    r = scan("\' OR 1=1--")
    assert r["detected"]
