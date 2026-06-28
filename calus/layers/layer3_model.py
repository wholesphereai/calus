"""
calus.layers.layer3_model — Layer 3: clean hook ONLY.

The trained guard model (Calus Guard) lives and is trained SEPARATELY. It is NOT
built or loaded here. This module is the seam it plugs into later.

Contract:
  * register a callable `model_layer(text, context) -> Signal | None`
    (or any object with a `.signal(text, context)` method).
  * the decision-maker invokes it ONLY on genuinely uncertain + HIGH-consequence
    cases — never on traffic the deterministic layers already resolved.
  * SECURITY INVARIANT: a jailbroken/compromised Layer 3 can only *emit a signal*.
    It can never block or unblock on its own. The deterministic decision-maker
    treats its signal like any other and never lets it downgrade an L1/L2 block.
    (Enforced in calus.decision, not here.)

Default state: no model registered -> the decision-maker simply never escalates to
it, and the deterministic path stands alone.
"""
from __future__ import annotations
from typing import Callable, Optional, Protocol, runtime_checkable

from ..signals import Signal, AgentContext


@runtime_checkable
class ModelLayer(Protocol):
    name: str
    def signal(self, text: str, context) -> Optional[Signal]:
        ...


# module-global registration slot (single process-wide model hook)
_MODEL_LAYER = None


def register_model_layer(layer) -> None:
    """Register the Layer-3 model hook. Accepts either an object exposing
    `.signal(text, context)` or a bare callable `(text, context) -> Signal|None`."""
    global _MODEL_LAYER
    if layer is not None and not (hasattr(layer, "signal") or callable(layer)):
        raise TypeError("model layer must be callable or expose a .signal() method")
    _MODEL_LAYER = layer


def clear_model_layer() -> None:
    global _MODEL_LAYER
    _MODEL_LAYER = None


def get_model_layer():
    """Return the registered hook, or None. The decision-maker calls this lazily."""
    return _MODEL_LAYER


def invoke(text: str, context, layer=None) -> Optional[Signal]:
    """Invoke the model hook defensively. Any error -> None (the deterministic
    layers must never be taken down by a flaky/compromised model)."""
    layer = layer if layer is not None else _MODEL_LAYER
    if layer is None:
        return None
    try:
        if hasattr(layer, "signal"):
            out = layer.signal(text, context)
        else:
            out = layer(text, context)
    except Exception:
        return None
    return out if isinstance(out, Signal) else None
