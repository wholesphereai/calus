"""
Exhaustive decision-matrix, conflict-resolution, failure-mode, invariant, and
auditability tests for the deterministic decision-maker.

Uses STUB layers so every path is driven deterministically and independently of
the real detectors. The decision-maker is a pure signal-combiner, so its entire
behaviour is a function of (usable signals, consequence, degraded).
"""
import pytest

from calus.signals import Signal, Verdict, Confidence, Consequence
from calus.decision import DecisionMaker, RULES, POLICY
from calus.decision.decision_maker import DecisionAction, LayerTrace
from calus.layers import layer3_model

H, M, L = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW
HC, LC = Consequence.HIGH, Consequence.LOW
BLOCK, PASS, UNC = Verdict.BLOCK, Verdict.PASS, Verdict.UNCERTAIN
A_BLOCK, A_FLAG, A_PASS = DecisionAction.BLOCK, DecisionAction.FLAG, DecisionAction.PASS


def sig(verdict, conf, cons=LC, layer="layer1_patterns", reasons=None):
    return Signal(layer, verdict, conf, surface="x", consequence=cons,
                  reasons=reasons or ["stub"])


class SignalStub:
    def __init__(self, signal, name):
        self._s = signal; self.name = name
    def signal(self, text, ctx):
        return self._s


class RaiseStub:
    def __init__(self, name): self.name = name
    def signal(self, text, ctx):
        raise ValueError("boom")


class ReturnStub:
    """Returns an arbitrary (possibly malformed) value."""
    def __init__(self, name, value): self.name = name; self._v = value
    def signal(self, text, ctx):
        return self._v


def dm(l1, l2, use_model=False):
    return DecisionMaker(layer1=l1, layer2=l2, use_model=use_model)


def L1(s): return SignalStub(s, "layer1_patterns")
def L2(s): return SignalStub(s, "layer2_flowgraph")


def teardown_function():
    layer3_model.clear_model_layer()


# --------------------------------------------------------------------------- #
# 1. The decision matrix (no model; deterministic over L1+L2)
# --------------------------------------------------------------------------- #
MATRIX = [
    # id,                      l1,                  l2,                  action,  rule
    ("clean_low",              sig(PASS, H, LC),    sig(PASS, H, LC),    A_PASS,  "R7_PASS"),
    ("clean_high_trusted",     sig(PASS, H, HC),    sig(PASS, H, HC),    A_PASS,  "R7_PASS"),
    ("l1_highblock_high",      sig(BLOCK, H, HC),   sig(PASS, H, HC),    A_BLOCK, "R1_BLOCK_HIGH"),
    ("l1_highblock_low",       sig(BLOCK, H, LC),   sig(PASS, H, LC),    A_BLOCK, "R2_BLOCK_LOW"),
    ("l2_highblock_high",      sig(PASS, H, HC),    sig(BLOCK, H, HC),   A_BLOCK, "R1_BLOCK_HIGH"),
    ("l2_highblock_low",       sig(PASS, H, LC),    sig(BLOCK, H, LC),   A_BLOCK, "R2_BLOCK_LOW"),
    ("softblock_high",         sig(PASS, H, HC),    sig(BLOCK, M, HC),   A_BLOCK, "R3_SAFEDEFAULT_HIGH"),
    ("softblock_low",          sig(PASS, H, LC),    sig(BLOCK, M, LC),   A_FLAG,  "R4_SAFEDEFAULT_LOW"),
    ("uncertain_high",         sig(PASS, H, HC),    sig(UNC, L, HC),     A_BLOCK, "R3_SAFEDEFAULT_HIGH"),
    ("uncertain_low",          sig(PASS, H, LC),    sig(UNC, L, LC),     A_FLAG,  "R4_SAFEDEFAULT_LOW"),
    ("l1_softblock_high",      sig(BLOCK, M, HC),   sig(PASS, H, HC),    A_BLOCK, "R3_SAFEDEFAULT_HIGH"),
    ("l1_softblock_low",       sig(BLOCK, M, LC),   sig(PASS, H, LC),    A_FLAG,  "R4_SAFEDEFAULT_LOW"),
    ("l1_uncertain_high",      sig(UNC, M, HC),     sig(PASS, H, HC),    A_BLOCK, "R3_SAFEDEFAULT_HIGH"),
    ("l1_uncertain_low",       sig(UNC, M, LC),     sig(PASS, H, LC),    A_FLAG,  "R4_SAFEDEFAULT_LOW"),
]


@pytest.mark.parametrize("name,l1,l2,action,rule", MATRIX, ids=[r[0] for r in MATRIX])
def test_decision_matrix(name, l1, l2, action, rule):
    d = dm(L1(l1), L2(l2)).decide("x", {})
    assert d.action is action, f"{name}: {d.action} != {action} (rule {d.rule})"
    assert d.rule == rule, f"{name}: {d.rule} != {rule}"
    assert d.rule in RULES


# --------------------------------------------------------------------------- #
# 2. Conflict resolution — explicit disagreement combinations
# --------------------------------------------------------------------------- #
def test_conflict_block_vs_pass_high_block_wins():
    d = dm(L1(sig(BLOCK, H, HC)), L2(sig(PASS, H, HC))).decide("x", {})
    assert d.action is A_BLOCK and d.rule == "R1_BLOCK_HIGH"


def test_conflict_pass_vs_block_high_block_wins():
    d = dm(L1(sig(PASS, H, HC)), L2(sig(BLOCK, H, HC))).decide("x", {})
    assert d.action is A_BLOCK


def test_conflict_confirmed_block_low_consequence_blocks():
    # a CONFIRMED (high-confidence) block is an attack -> the decision engine blocks
    # it even with no high-consequence action pending.
    d = dm(L1(sig(BLOCK, H, LC)), L2(sig(PASS, H, LC))).decide("x", {})
    assert d.action is A_BLOCK and d.rule == "R2_BLOCK_LOW"


# --------------------------------------------------------------------------- #
# 3. Model (Layer 3): additive only, gated, never unblocks/softens HIGH
# --------------------------------------------------------------------------- #
def _count_model(signal_to_return):
    calls = []
    def fn(text, ctx):
        calls.append(1)
        return signal_to_return
    return fn, calls


def test_model_adds_block_on_uncertain_high():
    fn, calls = _count_model(sig(BLOCK, H, HC, layer="layer3_model"))
    layer3_model.register_model_layer(fn)
    d = dm(L1(sig(PASS, H, HC)), L2(sig(UNC, M, HC)), use_model=True).decide("x", {})
    assert calls, "model must be consulted on uncertain + HIGH"
    assert d.action is A_BLOCK and d.escalated


def test_model_pass_cannot_soften_high_consequence():
    # model screams PASS, but L2 uncertain + HIGH consequence still safe-defaults to block
    fn, calls = _count_model(sig(PASS, H, HC, layer="layer3_model"))
    layer3_model.register_model_layer(fn)
    d = dm(L1(sig(PASS, H, HC)), L2(sig(UNC, M, HC)), use_model=True).decide("x", {})
    assert calls and d.escalated
    assert d.action is A_BLOCK and d.rule == "R3_SAFEDEFAULT_HIGH"


def test_model_not_consulted_on_low_consequence():
    fn, calls = _count_model(sig(BLOCK, H, LC, layer="layer3_model"))
    layer3_model.register_model_layer(fn)
    d = dm(L1(sig(PASS, H, LC)), L2(sig(UNC, M, LC)), use_model=True).decide("x", {})
    assert not calls, "model must NOT run on low-consequence"
    assert d.action is A_FLAG and not d.escalated


def test_model_not_consulted_when_decisive_high_block():
    fn, calls = _count_model(sig(PASS, H, HC, layer="layer3_model"))
    layer3_model.register_model_layer(fn)
    d = dm(L1(sig(BLOCK, H, HC)), L2(sig(PASS, H, HC)), use_model=True).decide("x", {})
    assert not calls
    assert d.action is A_BLOCK


def test_absent_model_is_not_degradation():
    layer3_model.clear_model_layer()
    d = dm(L1(sig(PASS, H, HC)), L2(sig(UNC, M, HC)), use_model=True).decide("x", {})
    assert d.action is A_BLOCK and not d.degraded and not d.escalated
    l3 = [t for t in d.trace if t.layer == "layer3_model"][0]
    assert l3.status == "absent"


# --------------------------------------------------------------------------- #
# 4. Failure modes — fail-safe, never crash
# --------------------------------------------------------------------------- #
# Note: DecisionMaker(layer1=None) intentionally substitutes the DEFAULT layer (that
# is the normal `DecisionMaker()` path), so an "absent/invalid layer" is simulated
# with a non-layer object() — which _invoke_layer classifies as status "absent".
@pytest.mark.parametrize("bad_l1", [
    RaiseStub("layer1_patterns"),
    ReturnStub("layer1_patterns", None),
    ReturnStub("layer1_patterns", "not a signal"),
    object(),                                        # invalid/absent required layer
])
def test_l1_failure_high_consequence_failsafe_blocks(bad_l1):
    d = dm(bad_l1, L2(sig(PASS, H, HC))).decide("x", {})
    assert d.action is A_BLOCK and d.rule == "R5_DEGRADED_HIGH"
    assert d.degraded is True


@pytest.mark.parametrize("bad_l1", [
    RaiseStub("layer1_patterns"),
    ReturnStub("layer1_patterns", None),
    object(),
])
def test_l1_failure_low_consequence_falls_back_to_clean(bad_l1):
    # one layer hiccups on benign LOW-consequence traffic, the other is clean -> pass
    d = dm(bad_l1, L2(sig(PASS, H, LC))).decide("x", {})
    assert d.action is A_PASS and d.rule == "R7_PASS"
    assert d.degraded is True


def test_block_still_wins_despite_degradation():
    # L1 malformed (degraded) but L2 high-block -> block wins over degradation
    d = dm(ReturnStub("layer1_patterns", 123), L2(sig(BLOCK, H, HC))).decide("x", {})
    assert d.action is A_BLOCK and d.rule == "R1_BLOCK_HIGH" and d.degraded


def test_both_layers_fail_high_consequence_from_context_blocks():
    d = dm(RaiseStub("layer1_patterns"), RaiseStub("layer2_flowgraph")).decide(
        "x", {"origin": "tool_response", "tool_calls": [{"name": "run_bash"}]})
    assert d.action is A_BLOCK and d.rule == "R5_DEGRADED_HIGH" and d.degraded


def test_both_layers_fail_low_consequence_flags():
    d = dm(RaiseStub("layer1_patterns"), RaiseStub("layer2_flowgraph")).decide("x", {})
    assert d.action is A_FLAG and d.rule == "R6_DEGRADED_LOW" and d.degraded


def test_model_error_during_escalation_is_safe_and_degraded():
    def boom(text, ctx):
        raise RuntimeError("model down")
    layer3_model.register_model_layer(boom)
    d = dm(L1(sig(PASS, H, HC)), L2(sig(UNC, M, HC)), use_model=True).decide("x", {})
    assert d.action is A_BLOCK              # safe default holds regardless
    assert d.degraded is True              # model present but broke
    l3 = [t for t in d.trace if t.layer == "layer3_model"][0]
    assert l3.status == "error"


def test_model_malformed_during_escalation_is_safe():
    layer3_model.register_model_layer(lambda text, ctx: {"verdict": "block"})
    d = dm(L1(sig(PASS, H, HC)), L2(sig(UNC, M, HC)), use_model=True).decide("x", {})
    assert d.action is A_BLOCK and d.degraded
    l3 = [t for t in d.trace if t.layer == "layer3_model"][0]
    assert l3.status == "malformed"


def test_decide_never_raises_on_total_failure():
    d = dm(object(), object()).decide("x", {})    # both required layers invalid/absent
    assert isinstance(d.action, DecisionAction)   # produced a decision, no crash
    assert d.degraded is True


# --------------------------------------------------------------------------- #
# 5. Determinism
# --------------------------------------------------------------------------- #
def test_determinism_same_input_same_decision():
    maker = dm(L1(sig(BLOCK, M, HC)), L2(sig(UNC, L, HC)))
    a = maker.decide("x", {})
    b = maker.decide("x", {})
    assert (a.action, a.rule, a.consequence, a.degraded) == \
           (b.action, b.rule, b.consequence, b.degraded)
    assert [t.status for t in a.trace] == [t.status for t in b.trace]


# --------------------------------------------------------------------------- #
# 6. Auditability
# --------------------------------------------------------------------------- #
def test_trace_has_every_layer_in_order():
    d = dm(L1(sig(PASS, H, LC)), L2(sig(PASS, H, LC))).decide("x", {})
    assert [t.layer for t in d.trace] == ["layer1_patterns", "layer2_flowgraph", "layer3_model"]
    assert all(isinstance(t, LayerTrace) and t.status for t in d.trace)


def test_explain_is_structured_and_complete():
    d = dm(L1(sig(BLOCK, H, HC)), L2(sig(PASS, H, HC))).decide("x", {})
    ex = d.explain()
    for k in ("action", "rule", "why", "consequence", "confidence", "surface",
              "escalated", "degraded", "layers", "reasons", "owasp_llm", "cwe"):
        assert k in ex
    assert ex["rule"] in RULES and ex["why"] == RULES[ex["rule"]]
    assert len(ex["layers"]) == 3


def test_policy_is_the_single_surface():
    # the action maps come from POLICY, not hardcoded in the maker
    assert POLICY.action_for_block(HC) is A_BLOCK
    assert POLICY.action_for_block(LC) is A_BLOCK          # confirmed attack blocks at any consequence
    assert POLICY.action_for_safe_default(HC) is A_BLOCK
    assert POLICY.action_for_safe_default(LC) is A_FLAG    # uncertain at low consequence still flags
    assert POLICY.model_verification_enabled is False     # active softening stays OFF
