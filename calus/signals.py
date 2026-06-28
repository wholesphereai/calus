"""
calus.signals — the contract every layer speaks.

No layer ever blocks. Each layer emits ONLY a Signal; all signals flow into the
one deterministic decision-maker (`calus.decision`). This module also defines the
normalized AgentContext that layers read (origin/taint + pending/available
capabilities), so callers shape context once and every layer agrees on it.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .taxonomy import Taint, Tier, source_taint, sink_tier, classify_action, is_trusted


class Verdict(str, Enum):
    BLOCK = "block"
    PASS = "pass"
    UNCERTAIN = "uncertain"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Consequence(str, Enum):
    HIGH = "high"      # irreversible / external / costly  (RED-tier)
    LOW = "low"        # reversible / observe               (LOW-tier)


@dataclass
class Signal:
    """A single layer's read on one input. The decision-maker consumes these."""
    layer: str
    verdict: Verdict
    confidence: Confidence
    surface: str = ""
    consequence: Consequence = Consequence.LOW
    reasons: list = field(default_factory=list)
    owasp_llm: list = field(default_factory=list)
    owasp_agentic: list = field(default_factory=list)
    cwe: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    @property
    def is_block(self) -> bool:
        return self.verdict is Verdict.BLOCK

    @property
    def is_high(self) -> bool:
        return self.confidence is Confidence.HIGH


@dataclass
class Action:
    """A concrete or available capability, resolved to a taxonomy sink."""
    name: str
    surface: str
    tier: Tier
    pending: bool          # True = the agent is about to do this (tool_call);
                           # False = merely available (tool in the toolset)
    reason: str = ""


@dataclass
class AgentContext:
    """Normalized view of one agent turn. Layers read this; callers build it once.

    origin     — the delivery channel the *input* arrived on (a taxonomy surface).
                 FAIL-SAFE DEFAULT: "unknown" (untrusted). Only an *explicit*
                 `direct_prompt` is treated as the trusted user/principal; an
                 unset / unrecognized origin is untrusted and cannot bypass the
                 flow graph. Callers that know the input is the genuine user prompt
                 must say so explicitly (origin="direct_prompt").
    sanitized  — set True only after the flow passed an explicit allow/sanitize
                 node; clears the forbidden edge.
    """
    origin: str = "unknown"
    sanitized: bool = False
    actions: list[Action] = field(default_factory=list)   # resolved capabilities
    raw: dict = field(default_factory=dict)               # original context dict

    # ---- construction -----------------------------------------------------
    @classmethod
    def build(cls, ctx: Optional[dict]) -> "AgentContext":
        """Coerce a loose context dict into an AgentContext.

        Recognized keys:
          origin / surface / channel : str  -> delivery surface of the input
          sanitized                  : bool -> flow already sanitized
          tool_calls                 : list -> capabilities the agent is invoking now
          tools / available_tools    : list -> capabilities in the toolset (latent)

        tool_calls / tools accept either bare names (str) or dicts with a `name`
        (and optional `arguments`) — matching the OpenAI tool schema the proxy
        already extracts.
        """
        ctx = ctx or {}
        # FAIL-SAFE: unrecognized / missing origin -> "unknown" (untrusted), never
        # the trusted user prompt.
        origin = ctx.get("origin") or ctx.get("surface") or ctx.get("channel") or "unknown"
        sanitized = bool(ctx.get("sanitized", False))

        actions: list[Action] = []
        for item in (ctx.get("tool_calls") or []):
            a = _resolve_action(item, pending=True)
            if a:
                actions.append(a)
        for item in (ctx.get("tools") or ctx.get("available_tools") or []):
            a = _resolve_action(item, pending=False)
            if a:
                actions.append(a)
        return cls(origin=origin, sanitized=sanitized, actions=actions, raw=dict(ctx))

    # ---- derived helpers (pure dict reads) --------------------------------
    @property
    def origin_taint(self) -> Optional[Taint]:
        return source_taint(self.origin)

    @property
    def is_untrusted(self) -> bool:
        # FAIL-SAFE: untrusted unless EXPLICITLY the trusted user prompt. Covers
        # known-untrusted surfaces AND unknown/unlabeled origins.
        return not is_trusted(self.origin)

    def pending_red(self) -> list[Action]:
        return [a for a in self.actions if a.pending and a.tier is Tier.RED]

    def available_red(self) -> list[Action]:
        return [a for a in self.actions if a.tier is Tier.RED]

    @property
    def raw_pending_count(self) -> int:
        """Number of pending tool calls the caller supplied (mapped or not)."""
        return len(self.raw.get("tool_calls") or [])

    def has_unknown_action(self) -> bool:
        """True if a pending tool call could not be mapped to any taxonomy sink —
        the caller treats that as uncertain rather than safe."""
        mapped_pending = sum(1 for a in self.actions if a.pending)
        return self.raw_pending_count > mapped_pending


def _resolve_action(item, pending: bool) -> Optional[Action]:
    """Turn a tool-call/tool item (str or dict) into a resolved Action via the
    taxonomy action classifier."""
    if isinstance(item, str):
        name, args = item, ""
    elif isinstance(item, dict):
        name = item.get("name") or (item.get("function") or {}).get("name") or ""
        args = item.get("arguments") or (item.get("function") or {}).get("arguments") or ""
        if not isinstance(args, str):
            try:
                import json as _json
                args = _json.dumps(args)
            except Exception:
                args = str(args)
    else:
        return None
    hit = classify_action(name, args)
    if not hit:
        return None
    surface, tier, reason = hit
    return Action(name=name or surface, surface=surface, tier=tier,
                  pending=pending, reason=reason)


def consequence_of(ctx: AgentContext) -> Consequence:
    """The situational consequence for the decision-maker's safe-default rule.

    HIGH only when a RED-tier action is actually PENDING (the agent is about to do
    something irreversible/external). Mere *availability* of a RED tool is NOT high
    consequence on its own — otherwise every benign turn with a powerful toolset
    would safe-default to block. Latent untrusted+RED posture is surfaced by Layer 2
    as a flag, not escalated to a block here.
    """
    return Consequence.HIGH if ctx.pending_red() else Consequence.LOW
