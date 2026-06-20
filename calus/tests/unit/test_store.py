"""Unit tests for the learning store."""
import pytest, sys, os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"../.."))

from calus.learning import store

def test_add_and_retrieve(tmp_db):
    store.init()
    store.add_threat("test attack","test attack","high",["aho"],"test","node1")
    assert store.threat_count() >= 1

def test_upsert_pattern(tmp_db):
    store.init()
    pid = store.upsert_pattern("test phrase",r"\btest\s+phrase\b","test",0.9,0.95,0.99,5,2)
    assert pid > 0
    pats = store.load_active_patterns()
    assert all(p["status"]=="accepted" for p in pats) or len(pats)==0

def test_accept_reject(tmp_db):
    store.init()
    pid = store.upsert_pattern("attack phrase",r"\battack\b","test",0.8,0.9,0.95,3,1)
    store.accept(pid)
    active = store.load_active_patterns()
    ids = [p["id"] for p in active]
    assert pid in ids
    store.reject(pid)

def test_stats(tmp_db):
    store.init()
    s = store.stats()
    assert "threat_corpus" in s
    assert "patterns_total" in s
    assert "accepted" in s

def test_false_positive_tracking(tmp_db):
    store.init()
    pid = store.upsert_pattern("fp test",r"\bfp\b","test",0.8,0.9,0.95,3,1)
    store.accept(pid)
    store.report_fp(pid,"some benign text")
    s = store.stats()
    assert s["false_positives"] >= 1
