"""
calus.decision.policy — THE single configuration surface for the decision-maker.

Every confidence cutoff, consequence→action mapping, escalation gate, and decision
constant lives here and ONLY here, so the referee's behaviour is tunable and
auditable in one place — no magic numbers scattered through the logic. These are
the established defaults; centralizing them does not change behaviour.

The consequence *derivation* itself (`pending RED action → HIGH`, else LOW) is
`consequence_of()` in `calus/signals.py`; it has no numeric threshold to tune, so it
stays there and is referenced as part of this documented surface.
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum

from ..signals import Consequence


class DecisionAction(str, Enum):
    BLOCK = "block"        # enforced stop (gateway mode) / verdict = block
    FLAG = "flag"          # allow but flag + log
    PASS = "pass"          # clean


@dataclass(frozen=True)
class DecisionPolicy:
    # --- Layer-1 numeric confidence bands (engine_confidence float -> Confidence) ---
    l1_high_band: float = 0.66      # >= this  -> HIGH   (exact / decisive match)
    l1_med_floor: float = 0.40      # [floor, high) -> MEDIUM (fuzzy / similarity)

    # --- consequence -> action maps (the fixed decision rules) ---
    # a HIGH-confidence block signal resolves to:
    block_high: DecisionAction = DecisionAction.BLOCK     # HIGH consequence
    block_low: DecisionAction = DecisionAction.FLAG       # LOW  consequence
    # an unresolved / soft / degraded situation resolves to (safe default):
    safe_default_high: DecisionAction = DecisionAction.BLOCK
    safe_default_low: DecisionAction = DecisionAction.FLAG

    # --- escalation gate: consult the (optional) model ONLY on uncertain + HIGH ---
    escalate_only_on_high_consequence: bool = True

    # --- FUTURE, DISABLED: active softening by a *benchmarked* model. While off
    #     (the default) the engine is strictly additive — the model may ADD a block
    #     signal but can NEVER downgrade/remove one. Do not enable until the model is
    #     validated; an unvalidated model dismissing flags is a risk we do not take. ---
    model_verification_enabled: bool = False

    # ---- derived action selectors (read by the decision-maker; no logic here) ----
    def action_for_block(self, cons: Consequence) -> DecisionAction:
        """Action for a high-confidence block signal at this consequence."""
        return self.block_high if cons is Consequence.HIGH else self.block_low

    def action_for_safe_default(self, cons: Consequence) -> DecisionAction:
        """Action for an unresolved / soft / degraded situation at this consequence."""
        return self.safe_default_high if cons is Consequence.HIGH else self.safe_default_low


# The one instance the whole engine reads.
POLICY = DecisionPolicy()


# Stable rule ids + their human explanation (recorded on every Decision so the
# dashboard/developer can see exactly which rule fired and why).
RULES: dict[str, str] = {
    "R1_BLOCK_HIGH":       "high-confidence block signal on a HIGH-consequence action → block",
    "R2_BLOCK_LOW":        "high-confidence block signal on a LOW-consequence action → flag + log",
    "R3_SAFEDEFAULT_HIGH": "unresolved signal (soft block / uncertain) on a HIGH-consequence action → safe-default block",
    "R4_SAFEDEFAULT_LOW":  "unresolved signal (soft block / uncertain) on a LOW-consequence action → flag + allow",
    "R5_DEGRADED_HIGH":    "a required layer failed/was absent on a HIGH-consequence action → fail-safe block",
    "R6_DEGRADED_LOW":     "a layer failed with no usable signal on a LOW-consequence action → flag",
    "R7_PASS":             "no block signal and no degradation → pass",
}
