"""
calus.patterns
~~~~~~~~~~~~~~
Pattern registry. Import this package to populate the detection registry
from the bundled threat-pattern library.
"""
from calus.patterns.loader import bootstrap as _bootstrap, pattern_stats
from calus.patterns.base import all_patterns, by_severity, Pattern, register

# Load any first-party community pattern modules (each calls register()).
try:
    __import__("calus.patterns.community")
except Exception:  # pragma: no cover - a bad module must not break import
    pass

__all__ = ["all_patterns", "by_severity", "pattern_stats", "Pattern", "register"]
