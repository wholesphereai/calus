"""
Braille encoding attack detector.
Catches attacks encoded in Unicode Braille patterns (U+2800-U+28FF).
Inspired by: calus BrailleConverter.
"""
import re

_BRAILLE_RANGE = re.compile(r"[\u2800-\u28FF]{4,}")

_BRAILLE_MAP = {
    '\u2801':'a','\u2803':'b','\u2809':'c','\u2819':'d','\u2811':'e',
    '\u280b':'f','\u281b':'g','\u2813':'h','\u280a':'i','\u281a':'j',
    '\u2805':'k','\u2807':'l','\u280d':'m','\u281d':'n','\u2815':'o',
    '\u280f':'p','\u281f':'q','\u2817':'r','\u280e':'s','\u281e':'t',
    '\u2825':'u','\u2827':'v','\u283a':'w','\u282d':'x','\u283d':'y',
    '\u2835':'z','\u2800':' ',
}
_ATTACK_WORDS = {"ignore","bypass","jailbreak","override","unrestricted","dan"}

def _decode(text: str) -> str:
    return "".join(_BRAILLE_MAP.get(c, "?") for c in text)

def detect(text: str) -> dict:
    m = _BRAILLE_RANGE.search(text)
    if not m:
        return {"detected": False, "severity": "none", "layer": "braille"}
    decoded = _decode(m.group(0))
    hit = any(w in decoded.lower() for w in _ATTACK_WORDS)
    return {
        "detected": hit,
        "severity": "high" if hit else "warning",
        "layer":    "braille",
        "decoded":  decoded[:200],
        "reason":   "Braille-encoded attack text detected",
    }
