"""calus.layers — signal emitters. None of them block; they only observe.

  Layer 1  patterns   (fast-path: known-attack pattern match)
  Layer 2  flow graph (taint x capability forbidden edges — the priority layer)
  Layer 3  model      (clean hook only; not built/trained here)
"""
from .layer1_patterns import PatternLayer
from .layer2_flowgraph import FlowGraphLayer
from .layer3_model import (
    ModelLayer, register_model_layer, get_model_layer, clear_model_layer,
)

__all__ = [
    "PatternLayer", "FlowGraphLayer",
    "ModelLayer", "register_model_layer", "get_model_layer", "clear_model_layer",
]
