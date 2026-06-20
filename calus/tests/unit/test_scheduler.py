"""Unit tests for the learning scheduler."""
import pytest, time, sys, os
sys.path.insert(0,os.path.join(os.path.dirname(__file__),"../.."))

from calus.learning.scheduler import LearningScheduler

def test_start_stop():
    sched = LearningScheduler(auto_every=1000, daily_hour=25)
    sched.start()
    assert sched._running
    sched.stop()
    assert not sched._running

def test_notify_doesnt_crash():
    sched = LearningScheduler(auto_every=1000)
    sched.start()
    sched.notify_threat()
    sched.stop()
