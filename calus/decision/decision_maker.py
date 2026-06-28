"""
calus.decision.decision_maker — the ONE deterministic decision-maker.

A pure **signal-combiner / referee**: it holds NO data and NO model, it never
detects anything itself. It only orchestrates the layers, combines their signals
with the consequence, and applies a fixed, documented rule table. It is the single
component that can produce a BLOCK.

Properties this module guarantees:
  * Deterministic — same signals + consequence → same decision, always. No hidden
    state, no randomness.
  * Auditable — every Decision carries the fired rule id, a per-layer trace
    (including absent/errored layers), and the reasons.
  * Fail-safe — a layer that is absent, raises, or returns malformed output is
    treated as "no usable signal"; the engine still produces a safe decision and
    never crashes the request. On a HIGH-consequence action, degradation fails
    toward safety (block).

All thresholds/constants live in `calus.decision.policy` (POLICY). The numbers are
not redefined here.

The fixed rule table (see policy.RULES for ids+text):

    given the usable signals U, the consequence C, and whether any layer degraded D:
      R1  any(BLOCK & HIGH-conf) in U,  C=HIGH                 -> BLOCK
      R2  any(BLOCK & HIGH-conf) in U,  C=LOW                  -> FLAG
      R3  any(BLOCK soft | UNCERTAIN) in U,  C=HIGH            -> BLOCK   (safe default)
      R4  any(BLOCK soft | UNCERTAIN) in U,  C=LOW             -> FLAG    (safe default)
      R5  D,  C=HIGH                                           -> BLOCK   (fail-safe)
      R6  D,  C=LOW,  no clean usable signal                   -> FLAG
      R7  otherwise (all usable signals clean PASS)            -> PASS

Conflict resolution is therefore explicit and consequence-aware: *any block signal
on a HIGH-consequence action wins* (safe default), and the model (Layer 3) is
strictly additive — it can ADD a block signal but can NEVER downgrade or remove
one. Active "softening" of low-consequence flags by a benchmarked model is a
documented FUTURE option gated behind POLICY.model_verification_enabled (off).
"""
from __future__ import annotations
from dataclasses import dataclass, field

from ..signals import (
    AgentContext, Signal, Verdict, Confidence, Consequence, consequence_of, Action,
)
from .policy import POLICY, RULES, DecisionAction
from ..layers.layer1_patterns import PatternLayer
from ..layers.layer2_flowgraph import FlowGraphLayer
from ..layers import layer3_model

# canonical layer order, used to render a complete trace even for layers that did
# not run on a given decision
_LAYER_ORDER = ("layer1_patterns", "layer2_flowgraph", "layer3_model")


@dataclass
class LayerTrace:
    """Per-layer audit record. `status`: ok | absent | error | malformed | skipped."""
    layer: str
    ran: bool
    status: str
    verdict: str = ""
    confidence: str = ""
    consequence: str = ""
    reasons: list = field(default_factory=list)
    error: str = ""

    def as_dict(self) -> dict:
        return {
            "layer": self.layer, "ran": self.ran, "status": self.status,
            "verdict": self.verdict, "confidence": self.confidence,
            "consequence": self.consequence, "reasons": list(self.reasons),
            "error": self.error,
        }


@dataclass
class Decision:
    action: DecisionAction
    consequence: Consequence
    rule: str = ""                 # which rule fired (id in policy.RULES)
    why: str = ""                  # human explanation of the fired rule
    surface: str = ""
    confidence: Confidence = Confidence.LOW
    degraded: bool = False         # a layer was absent/errored/malformed
    escalated: bool = False        # the model layer was consulted
    signals: list = field(default_factory=list)
    layers_run: list = field(default_factory=list)
    trace: list = field(default_factory=list)        # list[LayerTrace] — every layer
    reasons: list = field(default_factory=list)
    owasp_llm: list = field(default_factory=list)
    owasp_agentic: list = field(default_factory=list)
    cwe: list = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        """True for anything that is not a clean pass (block or flag)."""
        return self.action is not DecisionAction.PASS

    @property
    def blocked(self) -> bool:
        return self.action is DecisionAction.BLOCK

    def explain(self) -> dict:
        """Complete, structured explanation of this decision (dashboard-ready)."""
        return {
            "action": self.action.value,
            "rule": self.rule,
            "why": self.why,
            "consequence": self.consequence.value,
            "confidence": self.confidence.value,
            "surface": self.surface,
            "escalated": self.escalated,
            "degraded": self.degraded,
            "layers": [t.as_dict() for t in self.trace],
            "owasp_llm": list(self.owasp_llm),
            "owasp_agentic": list(self.owasp_agentic),
            "cwe": list(self.cwe),
            "reasons": list(self.reasons),
        }


class DecisionMaker:
    def __init__(self, layer1=None, layer2=None, use_model: bool = True):
        self.l1 = layer1 if layer1 is not None else PatternLayer()
        self.l2 = layer2 if layer2 is not None else FlowGraphLayer()
        self.use_model = use_model

    # ---- orchestration ----------------------------------------------------
    def decide(self, text: str, context=None) -> Decision:
        ctx = context if isinstance(context, AgentContext) else AgentContext.build(context)
        signals: list[Signal] = []
        layers_run: list[str] = []
        trace: list[LayerTrace] = []
        degraded = False

        # --- Layer 1: pattern fast-path ---
        s1, t1 = self._invoke_layer(self.l1, "layer1_patterns", text, ctx)
        trace.append(t1)
        if t1.status == "ok":
            signals.append(s1); layers_run.append(self.l1.name)
            if s1.is_block and s1.is_high:                 # decisive -> stop early
                return self._build(signals, ctx, layers_run, trace, escalated=False,
                                   degraded=degraded)
        else:
            degraded = True                                 # L1 is a required layer

        # --- Layer 2: capability-flow graph (always consulted; cheap & priority) ---
        s2, t2 = self._invoke_layer(self.l2, "layer2_flowgraph", text, ctx)
        trace.append(t2)
        if t2.status == "ok":
            signals.append(s2); layers_run.append(self.l2.name)
        else:
            degraded = True                                 # L2 is a required layer

        # decisive after L1+L2? (a HIGH-confidence block, or a fully clean pass with
        # no degradation)
        if self._has_high_block(signals):
            return self._build(signals, ctx, layers_run, trace, escalated=False,
                               degraded=degraded)
        if signals and not degraded and self._all_clean_pass(signals):
            return self._build(signals, ctx, layers_run, trace, escalated=False,
                               degraded=degraded)

        # --- escalation: consult Layer 3 (model) ONLY on uncertain + HIGH-consequence ---
        cons = self._consequence(signals, ctx)
        escalated = False
        if self.use_model and POLICY.escalate_only_on_high_consequence and cons is Consequence.HIGH:
            model = layer3_model.get_model_layer()
            s3, t3 = self._invoke_layer(model, "layer3_model", text, ctx)
            trace.append(t3)
            if t3.status == "ok":
                signals.append(s3)
                layers_run.append(getattr(s3, "layer", "layer3_model"))
                escalated = True
            elif t3.status in ("error", "malformed"):
                degraded = True                             # model present but broken
            # status == "absent": model simply not registered -> NOT a degradation

        return self._build(signals, ctx, layers_run, trace, escalated=escalated,
                           degraded=degraded)

    # ---- fail-safe single-layer invocation --------------------------------
    @staticmethod
    def _invoke_layer(layer, name: str, text: str, ctx) -> tuple:
        """Call one layer defensively. Returns (Signal|None, LayerTrace). Never
        raises — a flaky/compromised/absent layer becomes 'no usable signal'."""
        if layer is None or not (hasattr(layer, "signal") or callable(layer)):
            return None, LayerTrace(name, ran=False, status="absent")
        try:
            sig = layer.signal(text, ctx) if hasattr(layer, "signal") else layer(text, ctx)
        except Exception as e:                              # noqa: BLE001 — referee must not crash
            return None, LayerTrace(name, ran=True, status="error",
                                    error=f"{type(e).__name__}: {e}")
        if not isinstance(sig, Signal):
            return None, LayerTrace(name, ran=True, status="malformed",
                                    error=f"returned {type(sig).__name__}, expected Signal")
        return sig, LayerTrace(
            name, ran=True, status="ok",
            verdict=sig.verdict.value, confidence=sig.confidence.value,
            consequence=sig.consequence.value, reasons=list(sig.reasons),
        )

    # ---- the explicit rule table ------------------------------------------
    @staticmethod
    def _resolve(signals, ctx, degraded) -> tuple:
        """Pure function of (usable signals, consequence, degraded) -> (action, rule).
        This is the entire decision logic; it does NOT inspect text or detect."""
        cons = DecisionMaker._consequence(signals, ctx)
        has_high_block = any(s.is_block and s.is_high for s in signals)
        has_soft = any((s.is_block and not s.is_high) or s.verdict is Verdict.UNCERTAIN
                       for s in signals)
        has_clean = any(s.verdict is Verdict.PASS for s in signals)

        if has_high_block:
            rule = "R1_BLOCK_HIGH" if cons is Consequence.HIGH else "R2_BLOCK_LOW"
            return POLICY.action_for_block(cons), rule, cons
        if has_soft:
            rule = "R3_SAFEDEFAULT_HIGH" if cons is Consequence.HIGH else "R4_SAFEDEFAULT_LOW"
            return POLICY.action_for_safe_default(cons), rule, cons
        if degraded:
            if cons is Consequence.HIGH:
                return POLICY.action_for_safe_default(cons), "R5_DEGRADED_HIGH", cons
            if not has_clean:
                return POLICY.action_for_safe_default(cons), "R6_DEGRADED_LOW", cons
            # degraded but a clean usable signal covers this LOW-consequence flow -> pass
        return DecisionAction.PASS, "R7_PASS", cons

    # ---- helpers ----------------------------------------------------------
    @staticmethod
    def _has_high_block(signals) -> bool:
        return any(s.is_block and s.is_high for s in signals)

    @staticmethod
    def _all_clean_pass(signals) -> bool:
        return all(s.verdict is Verdict.PASS and s.is_high for s in signals)

    @staticmethod
    def _consequence(signals, ctx) -> Consequence:
        # consequence is derived from context (pending RED action) and any signal that
        # asserts HIGH — robust to a layer failing, since consequence_of reads ctx.
        if any(s.consequence is Consequence.HIGH for s in signals):
            return Consequence.HIGH
        return consequence_of(ctx)

    @staticmethod
    def _complete_trace(trace: list) -> list:
        """Ensure the trace has one entry per layer, in canonical order; layers that
        never ran are recorded as 'skipped' so the audit shows the full picture."""
        seen = {t.layer for t in trace}
        for name in _LAYER_ORDER:
            if name not in seen:
                trace.append(LayerTrace(name, ran=False, status="skipped"))
        order = {n: i for i, n in enumerate(_LAYER_ORDER)}
        trace.sort(key=lambda t: order.get(t.layer, 99))
        return trace

    # ---- assemble the Decision -------------------------------------------
    def _build(self, signals, ctx, layers_run, trace, escalated, degraded) -> Decision:
        action, rule, cons = self._resolve(signals, ctx, degraded)
        self._complete_trace(trace)
        why = RULES.get(rule, "")

        def union(attr):
            seen, out = set(), []
            for s in signals:
                for x in getattr(s, attr, []) or []:
                    if x and x not in seen:
                        seen.add(x); out.append(x)
            return out

        reasons = [f"{rule}: {why}"]
        for s in signals:
            for r in s.reasons:
                reasons.append(f"[{s.layer}] {r}")
        for t in trace:
            if t.status in ("error", "malformed", "absent") and t.layer != "layer3_model":
                reasons.append(f"[{t.layer}] DEGRADED ({t.status}): {t.error}".rstrip(": "))
            elif t.status in ("error", "malformed"):       # model degraded
                reasons.append(f"[{t.layer}] DEGRADED ({t.status}): {t.error}".rstrip(": "))

        block_sigs = [s for s in signals if s.is_block]
        lead = block_sigs[0] if block_sigs else (signals[0] if signals else None)
        return Decision(
            action=action,
            consequence=cons,
            rule=rule,
            why=why,
            surface=(lead.surface if lead else ""),
            confidence=(lead.confidence if lead else Confidence.LOW),
            degraded=degraded,
            escalated=escalated,
            signals=list(signals),
            layers_run=list(layers_run),
            trace=list(trace),
            reasons=reasons,
            owasp_llm=union("owasp_llm"),
            owasp_agentic=union("owasp_agentic"),
            cwe=union("cwe"),
        )


__all__ = ["DecisionMaker", "Decision", "DecisionAction", "LayerTrace", "Action"]
