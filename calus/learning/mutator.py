"""
CALUS.learning.mutator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Attack Mutation Engine.

Heuristic based on's transformation pipeline and calus's converter system.

Takes known attack phrases and auto-generates transformed variants:
 - Base64 encoded versions
 - ROT13 versions 
 - Leet speak variants
 - Spaced-out character versions
 - Reversed text versions
 - Atbash cipher versions
 - Mixed case variants
 - Punctuation-inserted variants

These variants are fed into the threat corpus so the self-improving
engine learns to detect obfuscated attacks automatically.
"""
from __future__ import annotations

import base64
import codecs
import random
import re
import string
from typing import List, Tuple


_LEET = str.maketrans("aeioAEIO", "43104310")

def _base64_encode(text: str) -> str:
    try: return base64.b64encode(text.encode()).decode()
    except: return ""

def _rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")

def _leet(text: str) -> str:
    return text.translate(_LEET)

def _spaced(text: str) -> str:
    return " ".join(text)

def _reversed_text(text: str) -> str:
    return text[::-1]

def _atbash(text: str) -> str:
    result = []
    for c in text:
        if "a" <= c <= "z": result.append(chr(ord("z") - (ord(c) - ord("a"))))
        elif "A" <= c <= "Z": result.append(chr(ord("Z") - (ord(c) - ord("A"))))
        else: result.append(c)
    return "".join(result)

def _random_caps(text: str) -> str:
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in text)

def _insert_punct(text: str) -> str:
    words = text.split()
    return ".".join(words)

def _zero_width(text: str) -> str:
    ZW = "\u200b"
    return ZW.join(text)

def _unicode_lookalike(text: str) -> str:
    subs = {"a":"а","e":"е","o":"о","i":"і","c":"с","p":"р"}
    return "".join(subs.get(c, c) for c in text)


MUTATIONS = [
    ("base64",       _base64_encode),
    ("rot13",        _rot13),
    ("leet",         _leet),
    ("spaced",       _spaced),
    ("reversed",     _reversed_text),
    ("atbash",       _atbash),
    ("random_caps",  _random_caps),
    ("dot_joined",   _insert_punct),
    ("zero_width",   _zero_width),
    ("unicode_sub",  _unicode_lookalike),
]


def mutate(text: str, mutations: list = None) -> List[Tuple[str, str]]:
    """
    Apply all (or specified) mutations to text.
    Returns list of (mutation_name, mutated_text) tuples.
    Skips mutations that produce empty or identical results.
    """
    active = [(name, fn) for name, fn in MUTATIONS if mutations is None or name in mutations]
    results = []
    for name, fn in active:
        try:
            mutated = fn(text)
            if mutated and mutated != text and len(mutated) < 2000:
                results.append((name, mutated))
        except Exception:
            pass
    return results


def seed_corpus_with_mutations(phrases: List[str], families: List[str] = None) -> int:
    """
    Take a list of known attack phrases, generate all mutations,
    and feed them into the threat corpus.

    This bootstraps the self-improving engine with obfuscated attack variants
    so it learns to mine patterns that detect obfuscated attacks.

    Returns number of variants added.
    """
    try:
        from calus.learning.store import add_threat
        from calus.learning.normalizer import normalize
    except ImportError:
        return 0

    count = 0
    for phrase in phrases:
        variants = mutate(phrase)
        for mutation_name, variant in variants:
            norm = normalize(variant)
            if norm:
                add_threat(
                    raw=variant[:500],
                    norm=norm[:500],
                    severity="high",
                    layers=[f"mutation:{mutation_name}"],
                    graph="mutator",
                    node=mutation_name,
                )
                count += 1
    return count


def generate_report(text: str) -> dict:
    """Generate a mutation analysis report for a given text."""
    variants = mutate(text)
    return {
        "original":       text,
        "mutation_count": len(variants),
        "mutations":      {name: val[:100] for name, val in variants},
    }
