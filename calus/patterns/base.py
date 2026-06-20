from __future__ import annotations
from dataclasses import dataclass, field
from typing import List
CRITICAL="critical"; HIGH="high"; MEDIUM="medium"; WARNING="warning"

@dataclass
class Pattern:
    text: str; family: str; severity: str; source: str
    tags: List[str] = field(default_factory=list)
    is_regex: bool = False; notes: str = ""

_REGISTRY: List[Pattern] = []
def register(*patterns): _REGISTRY.extend(patterns)
def all_patterns(): return list(_REGISTRY)
def by_source(s): return [p for p in _REGISTRY if p.source==s]
def by_family(f): return [p for p in _REGISTRY if p.family==f]
def by_severity(s): return [p for p in _REGISTRY if p.severity==s]
