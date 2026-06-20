"""
Binary/ASCII encoding attack detector.
Catches attacks encoded as binary strings (01001001 01100111 ...).
Inspired by: calus BinaryConverter.
"""
import re

_BIN_PATTERN = re.compile(r"\b([01]{8})([ ]+[01]{8}){4,}\b")
_ATTACK_WORDS = {"ignore","disregard","bypass","override","jailbreak","dan","system","unrestricted"}

def _decode(text: str) -> str:
    parts = text.split()
    chars = []
    for p in parts:
        if re.match(r"^[01]{8}$", p):
            try: chars.append(chr(int(p, 2)))
            except: pass
    return "".join(chars)

def detect(text: str) -> dict:
    m = _BIN_PATTERN.search(text)
    if not m:
        return {"detected": False, "severity": "none", "layer": "binary"}
    segment = m.group(0)
    decoded = _decode(segment)
    hit = any(w in decoded.lower() for w in _ATTACK_WORDS)
    return {
        "detected": hit,
        "severity": "high" if hit else "warning",
        "layer":    "binary",
        "decoded":  decoded[:200],
        "reason":   "Binary-encoded text detected",
    }
