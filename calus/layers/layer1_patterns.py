"""
calus.layers.layer1_patterns — Layer 1: pattern fast-path.

A cheap pre-filter that wraps the existing calibrated pattern engine
(`calus.detection` cascade: regex + obfuscation decoders + lexical similarity),
organized by the taxonomy's surfaces/categories rather than a raw dataset merge.

Emits ONLY a Signal:
  * decisive known-attack match  -> BLOCK, HIGH confidence   (exact-match)
  * fuzzy / similarity match      -> BLOCK, MEDIUM confidence  (so escalation fires)
  * clean miss                    -> PASS,  HIGH confidence   (flows on to Layer 2)

It does not decide and it does not consider capability flow — that is Layer 2.
Consequence is read from context so a pattern hit on a RED-capable turn is marked
HIGH consequence for the decision-maker.
"""
from __future__ import annotations

from ..signals import (
    AgentContext, Signal, Verdict, Confidence, Consequence, consequence_of,
)

class PatternLayer:
    name = "layer1_patterns"

    def __init__(self, detector=None):
        self._det = detector       # lazily resolved to the shared calus Detector

    def _detector(self):
        if self._det is None:
            from .. import api
            self._det = api.get_detector()
        return self._det

    def signal(self, text: str, context=None) -> Signal:
        ctx = context if isinstance(context, AgentContext) else AgentContext.build(context)
        cons = consequence_of(ctx)

        r = self._detector().scan(text or "")
        owasp = getattr(r, "owasp", "") or ""

        if not r.flagged:
            return Signal(
                layer=self.name, verdict=Verdict.PASS, confidence=Confidence.HIGH,
                surface=ctx.origin, consequence=cons,
                reasons=["no known-attack pattern matched"],
                owasp_llm=[owasp] if owasp else [],
            )

        conf = float(getattr(r, "confidence", 0.0) or 0.0)
        reasons = list(getattr(r, "reasons", []) or [])

        # exact / decisive vs fuzzy. Prefer the explicit signal in `reasons`
        # ("similar to known attack" => fuzzy), fall back to the confidence band.
        # Bands live in the single config surface (POLICY); lazy import avoids the
        # decision<->layers package import cycle.
        from ..decision.policy import POLICY
        is_fuzzy = any("similar to known attack" in str(x).lower() for x in reasons)
        if conf >= POLICY.l1_high_band and not is_fuzzy:
            band = Confidence.HIGH
        elif conf >= POLICY.l1_med_floor or is_fuzzy:
            band = Confidence.MEDIUM
        else:
            band = Confidence.LOW

        return Signal(
            layer=self.name, verdict=Verdict.BLOCK, confidence=band,
            surface=ctx.origin, consequence=cons,
            reasons=reasons or [f"pattern match (confidence {conf:.2f})"],
            owasp_llm=[owasp] if owasp else [],
            meta={"engine_confidence": round(conf, 3),
                  "tiers_run": list(getattr(r, "tiers_run", []) or []),
                  "decoded_from": getattr(r, "decoded_from", "") or ""},
        )
