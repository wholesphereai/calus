"""
Spaced-out character attack detector.
Catches "i g n o r e a l l i n s t r u c t i o n s" style evasion.
Inspired by: calus CharacterSpaceConverter.
"""
import re

_SPACED = re.compile(r"\b(\w)([ _\-.])\1*(?:(\w)\2\1*){3,}\b")
_ATTACK_WORDS = {"ignore","bypass","jailbreak","override","dan","disregard",
                 "forget","unrestricted","unlimited","system","prompt"}

def _collapse(text: str) -> str:
    return re.sub(r"(\w)[ _\-.]+(?=\w)", r"\1", text.lower())

def detect(text: str) -> dict:
    collapsed = _collapse(text)
    hit = any(w in collapsed for w in _ATTACK_WORDS)
    # Also check raw for the spaced pattern
    spaced_words = re.findall(r"\b\w([ ])\w(?:\1\w){2,}\b", text)
    if not spaced_words and not hit:
        return {"detected": False, "severity": "none", "layer": "charspace"}
    if spaced_words or hit:
        return {
            "detected": True,
            "severity": "high" if hit else "warning",
            "layer":    "charspace",
            "collapsed": collapsed[:200],
            "reason":   "Spaced-character obfuscation detected",
        }
    return {"detected": False, "severity": "none", "layer": "charspace"}
