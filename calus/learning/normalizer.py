"""
CALUS.learning.normalizer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Deep text normalization — strips every common obfuscation trick so the
miner and validator see the canonical form of an attack regardless of how
it was encoded.

Handles:
  - Leet speak / character substitution  (4→a, 3→e, @→a, $→s, 1→i, 0→o …)
  - Unicode homoglyphs                   (Cyrillic а → Latin a, etc.)
  - Zero-width / invisible characters
  - Excess whitespace & punctuation noise
  - URL encoding                         (%69%67%6e%6f%72%65 → ignore)
  - Base64 fragments
  - Rot13
  - HTML entities                        (&lt; → <)
  - Combining diacritical marks          (à → a)
  - Mixed case & repeated chars          (IIIIGNORE → ignore)
"""

from __future__ import annotations

import base64
import codecs
import re
import unicodedata
import urllib.parse
from functools import lru_cache
from typing import List

# ── Leet-speak map ────────────────────────────────────────────────────────────
_LEET: dict[str, str] = {
    '4': 'a', '@': 'a', '∂': 'a', 'ä': 'a', 'á': 'a', 'à': 'a',
    '3': 'e', '€': 'e', 'ë': 'e', 'é': 'e',
    '1': 'i', '!': 'i', '|': 'i', 'ï': 'i', 'í': 'i',
    '0': 'o', 'ò': 'o', 'ó': 'o', 'ö': 'o', 'ø': 'o',
    '5': 's', '$': 's', '§': 's',
    '7': 't', '+': 't',
    '6': 'g',
    '9': 'g',
    '2': 'z',
    '8': 'b',
    'ß': 'ss',
}

# ── Unicode homoglyph map (common Cyrillic/Greek → Latin) ────────────────────
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic
    'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o', 'р': 'p', 'с': 'c',
    'у': 'y', 'х': 'x', 'ѕ': 's', 'ј': 'j', 'ѵ': 'v', 'ԁ': 'd',
    'ԝ': 'w', 'ɡ': 'g', 'ᴏ': 'o', 'ᴀ': 'a',
    # Greek
    'α': 'a', 'β': 'b', 'γ': 'g', 'δ': 'd', 'ε': 'e', 'ζ': 'z',
    'η': 'n', 'θ': 'o', 'ι': 'i', 'κ': 'k', 'λ': 'l', 'μ': 'u',
    'ν': 'v', 'ξ': 'x', 'ο': 'o', 'π': 'p', 'ρ': 'r', 'σ': 's',
    'τ': 't', 'υ': 'u', 'φ': 'f', 'χ': 'x', 'ψ': 'ps', 'ω': 'w',
    # Full-width ASCII (Ａ → A)
    **{chr(0xFF01 + i): chr(0x21 + i) for i in range(94)},
}

# ── Zero-width & invisible chars ─────────────────────────────────────────────
_ZW_PATTERN = re.compile(
    r'[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060\u2062-\u2064'
    r'\u206a-\u206f\ufeff\u00ad]'
)

# ── Repeated-char collapse (IIIgnore → ignore) ───────────────────────────────
_REPEAT = re.compile(r'(.)\1{2,}')

# ── HTML entity pattern ───────────────────────────────────────────────────────
_HTML_ENT = re.compile(r'&[a-zA-Z]{2,8};|&#\d{1,6};|&#x[0-9a-fA-F]{1,6};')

# ── Base64 fragment pattern ───────────────────────────────────────────────────
_B64 = re.compile(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')


def _decode_html(text: str) -> str:
    try:
        import html
        return html.unescape(text)
    except Exception:
        return text


def _try_b64(m: re.Match) -> str:
    """Try to decode a base64 fragment; return decoded if it's printable text."""
    s = m.group(0)
    try:
        dec = base64.b64decode(s + '==').decode('utf-8', errors='ignore')
        if dec.isprintable() and len(dec) >= 4:
            return dec
    except Exception:
        pass
    return s


def _try_url_decode(text: str) -> str:
    try:
        decoded = urllib.parse.unquote(text)
        if decoded != text:
            return decoded
    except Exception:
        pass
    return text


def _try_rot13(text: str) -> str:
    """Only apply rot13 if the result looks more like natural language."""
    decoded = codecs.decode(text, 'rot_13')
    # Crude heuristic: more common English letters → more natural
    common = set('etaoinshrdlu ')
    orig_score = sum(1 for c in text.lower() if c in common)
    dec_score  = sum(1 for c in decoded.lower() if c in common)
    return decoded if dec_score > orig_score * 1.3 else text


def _apply_homoglyphs(text: str) -> str:
    return ''.join(_HOMOGLYPHS.get(c, c) for c in text)


def _apply_leet(text: str) -> str:
    result = []
    for c in text:
        result.append(_LEET.get(c, c))
    return ''.join(result)


def _strip_zw(text: str) -> str:
    return _ZW_PATTERN.sub('', text)


def _collapse_repeats(text: str) -> str:
    return _REPEAT.sub(r'\1\1', text)  # keep max 2


def _normalize_unicode(text: str) -> str:
    """NFKD decomposition then strip combining marks."""
    nfkd = unicodedata.normalize('NFKD', text)
    return ''.join(c for c in nfkd
                   if unicodedata.category(c) != 'Mn'  # Mn = combining mark
                   and c.isascii() or c in _HOMOGLYPHS)


@lru_cache(maxsize=4096)
def normalize(text: str) -> str:
    """
    Full normalization pipeline.
    Returns the canonical form used for pattern mining and matching.
    Cached — same input always returns same output.
    """
    t = text

    # 1. Strip zero-width/invisible chars
    t = _strip_zw(t)

    # 2. Decode HTML entities
    t = _decode_html(t)

    # 3. URL decode
    t = _try_url_decode(t)

    # 4. Expand base64 fragments
    t = _B64.sub(_try_b64, t)

    # 5. Unicode normalization + combining mark removal
    t = _normalize_unicode(t)

    # 6. Homoglyph substitution
    t = _apply_homoglyphs(t)

    # 7. Lowercase
    t = t.lower()

    # 8. Leet speak
    t = _apply_leet(t)

    # 9. Collapse repeated chars
    t = _collapse_repeats(t)

    # 10. Normalise whitespace
    t = re.sub(r'[\s\xa0\t\n\r]+', ' ', t).strip()

    # 11. Try rot13 if text looks scrambled
    if len(t) > 10 and re.search(r'\b[a-z]{4,}\b', t) is None:
        t = _try_rot13(t)

    return t


def tokenize(text: str) -> List[str]:
    """Split normalized text into word tokens, stripping punctuation."""
    norm = normalize(text)
    return [w for w in re.split(r'[^\w]+', norm) if w and len(w) >= 2]


def ngrams(text: str, n: int) -> List[str]:
    """Return word n-grams from normalized text."""
    tokens = tokenize(text)
    if len(tokens) < n:
        return []
    return [' '.join(tokens[i:i+n]) for i in range(len(tokens) - n + 1)]


def all_ngrams(text: str, min_n: int = 2, max_n: int = 6) -> List[str]:
    """Return all word n-grams in the given range."""
    result = []
    for n in range(min_n, max_n + 1):
        result.extend(ngrams(text, n))
    return result
