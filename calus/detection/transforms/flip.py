"""
Flipped/reversed text attack detector.
Catches reversed attacks like "snoitcurtsni suoiverp erongi".
Inspired by: calus FlipConverter.
"""
import re

_ATTACK_WORDS = {"ignore","disregard","bypass","override","jailbreak","unrestricted",
                 "dan","forget","instructions","system","prompt"}

def detect(text: str) -> dict:
    reversed_text = text[::-1].lower()
    hit = any(w in reversed_text for w in _ATTACK_WORDS)
    if not hit:
        return {"detected": False, "severity": "none", "layer": "flip"}
    return {
        "detected": True,
        "severity": "medium",
        "layer":    "flip",
        "decoded":  reversed_text[:200],
        "reason":   "Reversed/flipped attack text detected",
    }
