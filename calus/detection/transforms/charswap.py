"""
Character-swap attack detector.
Catches attacks with swapped adjacent characters (typosquatting).
Inspired by: calus CharSwapAttackConverter.
"""
import re

_ATTACK_WORDS = ["ignore","disregard","bypass","override","jailbreak","unrestricted","dan","forget"]

def _swap_variants(word: str):
    variants = set()
    for i in range(len(word) - 1):
        s = list(word)
        s[i], s[i+1] = s[i+1], s[i]
        variants.add("".join(s))
    return variants

_ALL_VARIANTS = {v: w for w in _ATTACK_WORDS for v in _swap_variants(w)}

def detect(text: str) -> dict:
    lower = text.lower()
    tokens = re.findall(r"\b\w+\b", lower)
    hits = [(_ALL_VARIANTS[t], t) for t in tokens if t in _ALL_VARIANTS]
    if not hits:
        return {"detected": False, "severity": "none", "layer": "charswap"}
    return {
        "detected": True,
        "severity": "medium",
        "layer":    "charswap",
        "matches":  hits[:5],
        "reason":   f"Charswap evasion: {hits[:3]}",
    }
