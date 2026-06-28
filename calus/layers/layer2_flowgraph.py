"""
calus.layers.layer2_flowgraph — Layer 2: the Capability-Flow Graph.

The PRIORITY deterministic layer. No ML, no I/O — just taint metadata and a
forbidden-edge check over the taxonomy's surfaces.

Technique (the HOW, applied to OUR taxonomy's surfaces):
  * taint-tracking / information-flow-control — content carries an origin taint
    (trusted vs untrusted), à la CaMeL capabilities & Microsoft FIDES labels;
  * capability metadata on actions — each pending/available tool resolves to a
    taxonomy SINK with a tier (RED/LOW);
  * forbidden edges — untrusted-origin -> RED-tier sink is blocked unless the flow
    passed a sanitize/allow node (the rule lives in calus.taxonomy);
  * tiering to preserve utility — LOW-tier flows always pass; trusted origins pass
    (Layer 1 owns user jailbreaks). Blocking *all* untrusted->tool destroys task
    completion (CaMeL strict mode ~67%), so we deliberately do not.
  * Rule-of-Two posture — when there's no concrete pending action but untrusted
    content meets a RED capability, we don't pass blindly: we emit UNCERTAIN so the
    decision-maker escalates / safe-defaults.

Output: a Signal only. This layer never decides.
"""
from __future__ import annotations

from ..signals import (
    AgentContext, Signal, Verdict, Confidence, Consequence, consequence_of,
)
from ..taxonomy import is_forbidden, labels_for, Tier


class FlowGraphLayer:
    name = "layer2_flowgraph"

    def signal(self, text: str, context=None) -> Signal:
        ctx = context if isinstance(context, AgentContext) else AgentContext.build(context)
        cons = consequence_of(ctx)

        # 1) Concrete forbidden edge: untrusted origin -> a pending RED sink.
        #    This is a structural, deterministic finding => BLOCK, HIGH confidence.
        for a in ctx.pending_red():
            if is_forbidden(ctx.origin, a.surface, sanitized=ctx.sanitized):
                lab = _merge_labels(ctx.origin, a.surface)
                return Signal(
                    layer=self.name, verdict=Verdict.BLOCK, confidence=Confidence.HIGH,
                    surface=ctx.origin, consequence=Consequence.HIGH,
                    reasons=[
                        f"forbidden edge: untrusted origin '{ctx.origin}' -> "
                        f"RED sink '{a.surface}' via {a.name!r} (unsanitized)",
                        a.reason,
                    ],
                    **lab,
                )

        # 2) Pending RED sink but trusted origin (user asked for it) -> allow, but
        #    flag the consequence as HIGH so Layer 1 / the decision-maker stay alert.
        pend_red = ctx.pending_red()
        if pend_red and not ctx.is_untrusted:
            return Signal(
                layer=self.name, verdict=Verdict.PASS, confidence=Confidence.HIGH,
                surface=ctx.origin, consequence=Consequence.HIGH,
                reasons=[f"trusted origin '{ctx.origin}' -> RED sink "
                         f"'{pend_red[0].surface}' (principal-authorized)"],
            )

        # 3) A pending action we could not classify, arriving from an UNTRUSTED
        #    origin -> uncertain (don't assume safe). From a TRUSTED principal an
        #    unknown action is authorized and must not be flagged (B3: this was
        #    over-flagging benign agent flows that use tools the classifier doesn't
        #    recognize).
        if ctx.has_unknown_action() and ctx.is_untrusted:
            return Signal(
                layer=self.name, verdict=Verdict.UNCERTAIN, confidence=Confidence.LOW,
                surface=ctx.origin, consequence=cons,
                reasons=["untrusted origin + pending tool call that did not map to a "
                         "known taxonomy sink"],
            )

        # 4) No pending action. Rule-of-Two posture: untrusted content + a RED
        #    capability in reach = worth surfacing, but there is no concrete action
        #    yet -> UNCERTAIN at LOW consequence, so the decision-maker FLAGS (logs)
        #    rather than blocking benign traffic. The actual block happens when the
        #    RED action is attempted (then pending_red -> HIGH consequence).
        if ctx.is_untrusted and ctx.available_red() and not pend_red:
            red = ctx.available_red()
            return Signal(
                layer=self.name, verdict=Verdict.UNCERTAIN, confidence=Confidence.MEDIUM,
                surface=ctx.origin, consequence=Consequence.LOW,
                reasons=[
                    "Rule-of-Two posture: untrusted content + RED capability in reach "
                    f"({', '.join(sorted({a.surface for a in red}))}) with no sanitize node",
                ],
            )

        # 5) Everything else is a clean low-consequence flow.
        return Signal(
            layer=self.name, verdict=Verdict.PASS, confidence=Confidence.HIGH,
            surface=ctx.origin, consequence=cons,
            reasons=["no forbidden capability-flow edge"],
        )


def _merge_labels(origin: str, sink: str) -> dict:
    """Union the OWASP/CWE labels of the origin surface and the sink surface, so a
    blocked edge reports both the injection vector and the abused capability."""
    a, b = labels_for(origin), labels_for(sink)
    def u(k):  # union preserving order, origin first
        seen, out = set(), []
        for x in a[k] + b[k]:
            if x not in seen:
                seen.add(x); out.append(x)
        return out
    return {"owasp_llm": u("owasp_llm"),
            "owasp_agentic": u("owasp_agentic"),
            "cwe": u("cwe")}
