"""
ASCII/Unicode tag smuggling detector.
Catches attacks hidden in invisible Unicode TAG characters (U+E0000–U+E007F).
Inspired by: calus ascii-smuggling plugin, calus ascii_smuggler_converter.
"""
import re, unicodedata

TAG_PATTERN = re.compile(r"[\U000E0000-\U000E007F]")

def _decode_tags(text: str) -> str:
    """Decode hidden text from Unicode tag block."""
    chars = []
    for ch in text:
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F:
            visible = cp - 0xE0000
            if 0x20 <= visible <= 0x7E:
                chars.append(chr(visible))
    return "".join(chars)

def detect(text: str) -> dict:
    tag_chars = TAG_PATTERN.findall(text)
    if not tag_chars:
        return {"detected": False, "severity": "none", "layer": "ascii_smuggle"}
    hidden = _decode_tags(text)
    return {
        "detected":   True,
        "severity":   "critical",
        "layer":      "ascii_smuggle",
        "tag_count":  len(tag_chars),
        "hidden_text": hidden[:200],
        "reason":     f"Unicode TAG smuggling detected ({len(tag_chars)} hidden chars)",
    }
