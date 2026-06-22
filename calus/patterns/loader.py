"""
CALUS.patterns.loader
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Bootstraps the learning engine's threat corpus with all pre-built patterns.
Runs automatically on first CALUS use — seeds the DB so learning starts
with a strong foundation instead of from zero.

NOTE: this register()/all_patterns() path is LEGACY and is not what the live
detector uses. The production rule loader is
calus.detection.scored_engine.build_from_package (an AST walk over the pattern
packages that compiles the ~27k active rules). The register() registry can be
empty (all_patterns() == 0) and that is expected.
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
    """Return statistics about loaded patterns, broken down by source.

    The registry is populated by register() calls made when sub-packages of
    calus.patterns are imported. Sources currently in use are "calus" (bundled),
    "community", and "user"; external packs (spikee/pyrit/promptfoo) were removed,
    so the registry can be empty. Keys are derived from the live registry so they
    stay meaningful regardless of which packs are present.
    """
    import calus.patterns
    from calus.patterns.base import all_patterns, by_source
    patterns = all_patterns()
    by_src = {}
    for p in patterns:
        by_src[p.source] = by_src.get(p.source, 0) + 1
    return {
        "total":     len(patterns),
        "bundled":   len(by_source("calus")),
        "community": len(by_source("community")),
        "user":      len(by_source("user")),
        "by_source": by_src,
    }
