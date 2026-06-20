"""
Morse code attack detector.
Catches attacks encoded in morse code to evade pattern matching.
Inspired by: calus MorseConverter, calus morse strategy.
"""
import re

_MORSE = {
    ".-":"a","-.":"b","-.-.":"c","-..":"d",".":"e","..-.":"f","--.":"g","....":"h",
    "..":"i",".---":"j","-.-":"k",".-..":"l","--":"m","-.":"n","---":"o",".--.":"p",
    "--.-":"q",".-.":"r","...":"s","-":"t","..-":"u","...-":"v",".--":"w","-..-":"x",
    "-.--":"y","--..":"z","-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",
    ".....":"5","-....":"6","--...":"7","---..":"8","----.":"9",
}

_MORSE_PATTERN = re.compile(r"^([.\-]{1,6})([ /][.\-]{1,6}){4,}$", re.MULTILINE)
_WORD_SEP = re.compile(r"[ /]+")

def _decode(text: str) -> str:
    words = re.split(r"\s*/\s*|\s{2,}", text.strip())
    decoded = []
    for word in words:
        chars = _WORD_SEP.split(word.strip())
        decoded.append("".join(_MORSE.get(c,"?") for c in chars if c))
    return " ".join(decoded)

_ATTACK_WORDS = {"ignore","disregard","forget","override","bypass","dan","jailbreak",
                 "system","prompt","instructions","restrictions","unlimited"}

def detect(text: str) -> dict:
    lines = text.strip().split("\n")
    for line in lines:
        line = line.strip()
        if _MORSE_PATTERN.match(line):
            decoded = _decode(line)
            hit = any(w in decoded.lower() for w in _ATTACK_WORDS)
            return {
                "detected": hit,
                "severity": "high" if hit else "warning",
                "layer":    "morse",
                "decoded":  decoded[:200],
                "reason":   "Morse-encoded text" + (" with attack keywords" if hit else ""),
            }
    return {"detected": False, "severity": "none", "layer": "morse"}
