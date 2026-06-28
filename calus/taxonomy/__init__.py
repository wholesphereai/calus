"""
calus.taxonomy — the single SOURCE OF TRUTH for the capability-flow graph.

Everything Layer 2 (and the decision-maker's consequence mapping) needs is
derived from `agent-security-taxonomy.md`:

  * the 16 access surfaces (identical names to the guard dataset),
  * which surfaces introduce UNTRUSTED content (taint origin),
  * which surfaces are RED-tier vs LOW-tier capability sinks,
  * the forbidden-edge rule (untrusted-origin -> RED sink, unless sanitized),
  * the OWASP-LLM / OWASP-Agentic / CWE labels per surface.

No rules are invented outside the taxonomy. Pure data + pure functions, so the
whole module is import-cheap and has zero I/O in the hot path.
"""
from .taxonomy import (
    SURFACES,
    SURFACE,
    Taint,
    Tier,
    Impact,
    source_taint,
    sink_tier,
    is_source,
    is_sink,
    is_trusted,
    is_forbidden,
    forbidden_edges,
    classify_action,
    labels_for,
)

__all__ = [
    "SURFACES", "SURFACE", "Taint", "Tier", "Impact",
    "source_taint", "sink_tier", "is_source", "is_sink", "is_trusted",
    "is_forbidden", "forbidden_edges", "classify_action", "labels_for",
]
