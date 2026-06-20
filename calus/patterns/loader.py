"""
CALUS.patterns.loader
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Bootstraps the learning engine's threat corpus with all pre-built patterns.
Runs automatically on first CALUS use — seeds the DB so learning starts
with a strong foundation instead of from zero.
"""
from __future__ import annotations
import logging
log = logging.getLogger(__name__)

_bootstrapped = False


def bootstrap(force: bool = False) -> int:
    """
    Load all patterns from the bundled calus pattern library into the threat corpus.
    Skips if already done (tracked in DB).
    Returns number of patterns loaded.
    """
    global _bootstrapped
    if _bootstrapped and not force:
        return 0

    try:
        from calus.learning.store import add_threat, threat_count
        from calus.learning.normalizer import normalize
        import calus.patterns  # triggers all register() calls

        from calus.patterns.base import all_patterns
        patterns = all_patterns()

        if threat_count() > len(patterns) // 2 and not force:
            _bootstrapped = True
            return 0  # already bootstrapped

        loaded = 0
        for p in patterns:
            try:
                norm = normalize(p.text)
                if norm:
                    add_threat(
                        raw=p.text[:2000],
                        norm=norm[:2000],
                        severity=p.severity,
                        layers=[p.family],
                        graph="bootstrap",
                        node=f"{p.source}:{p.family}",
                    )
                    loaded += 1
            except Exception as e:
                log.debug("pattern bootstrap error: %s", e)

        _bootstrapped = True
        log.info("[CALUS:loader] bootstrapped %d patterns into threat corpus", loaded)
        return loaded

    except Exception as exc:
        log.warning("[CALUS:loader] bootstrap failed: %s", exc)
        return 0


def pattern_stats() -> dict:
    """Return statistics about loaded patterns."""
    import calus.patterns
    from calus.patterns.base import all_patterns, by_source
    patterns = all_patterns()
    return {
        "total":     len(patterns),
        "bundled":   len(by_source("calus")),
        "community": len(by_source("calus")),
        "user":      len(by_source("user")),
    }
