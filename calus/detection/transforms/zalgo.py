"""
Zalgo / combining diacritical marks attack detector.
Catches heavily diacriticised text used to evade filters.
Inspired by: calus ZalgoConverter, DiacriticConverter.
"""
import re, unicodedata

_COMBINING = re.compile(r"\p{M}", re.UNICODE) if False else None  # fallback below

def _count_combining(text: str) -> int:
    return sum(1 for c in text if unicodedata.category(c) == "Mn")

def _strip_combining(text: str) -> str:
    import unicodedata as ud
    nfkd = ud.normalize("NFKD", text)
    return "".join(c for c in nfkd if ud.category(c) != "Mn")

_ATTACK_WORDS = {"ignore","disregard","bypass","override","jailbreak","unrestricted"}

def detect(text: str) -> dict:
    combining_count = _count_combining(text)
    ratio = combining_count / max(len(text), 1)
    if ratio < 0.15:
        return {"detected": False, "severity": "none", "layer": "zalgo"}
    stripped = _strip_combining(text)
    hit = any(w in stripped.lower() for w in _ATTACK_WORDS)
    return {
        "detected": True,
        "severity": "high" if hit else "warning",
        "layer":    "zalgo",
        "combining_ratio": round(ratio, 3),
        "stripped": stripped[:200],
        "reason":   f"Zalgo/combining-mark obfuscation (ratio={ratio:.2f})",
    }
