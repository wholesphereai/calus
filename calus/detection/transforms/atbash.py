"""
Atbash cipher attack detector.
Catches attacks encoded with atbash (a=z, b=y, ...).
Inspired by: calus AtbashConverter.
"""
import re

def _atbash(text: str) -> str:
    result = []
    for c in text:
        if 'a' <= c <= 'z': result.append(chr(ord('z') - (ord(c) - ord('a'))))
        elif 'A' <= c <= 'Z': result.append(chr(ord('Z') - (ord(c) - ord('A'))))
        else: result.append(c)
    return "".join(result)

_ATTACK_WORDS = {"ignore","disregard","bypass","override","jailbreak","unrestricted",
                 "dan","system","prompt","instructions","forget","restrictions"}

def detect(text: str) -> dict:
    decoded = _atbash(text)
    hit = any(w in decoded.lower() for w in _ATTACK_WORDS)
    if not hit:
        return {"detected": False, "severity": "none", "layer": "atbash"}
    return {
        "detected": True,
        "severity": "high",
        "layer":    "atbash",
        "decoded":  decoded[:200],
        "reason":   "Atbash-encoded attack text detected",
    }
