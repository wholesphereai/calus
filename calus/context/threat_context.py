"""
CALUS.context.threat_context
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Cross-turn threat memory for a proxy pipeline run.

Keeps a rolling window of threats seen so far in the current run.
The AI skills use this context to give heightened scrutiny when
a pipeline is already under attack.
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional


@dataclass
class ThreatEvent:
    node: str
    severity: str
    attack_types: List[str]
    preview: str
    turn: int


class ThreatContext:
    """
    Per-pipeline-run threat memory.
    One instance lives for the duration of a graph invocation.
    Thread-safe.
    """

    def __init__(self, max_history: int = 50):
        self._lock    = threading.Lock()
        self._history: Deque[ThreatEvent] = deque(maxlen=max_history)
        self._turn    = 0
        self._node_threat_count: Dict[str, int] = {}

    def record(self, node: str, scan_result: dict) -> None:
        """Record a scan result. Call for every message, detected or not."""
        with self._lock:
            self._turn += 1
            if scan_result.get("detected"):
                # Collect attack types from deterministic + AI layers
                attack_types: List[str] = []
                for layer_res in scan_result.get("layers", {}).values():
                    if isinstance(layer_res, dict) and layer_res.get("detected"):
                        if layer_res.get("attack_type"):
                            attack_types.append(layer_res["attack_type"])
                        elif layer_res.get("layer"):
                            attack_types.append(layer_res["layer"])
                for skill_res in scan_result.get("ai_skills", {}).get("skills_hit", []):
                    attack_types.append(skill_res.get("attack_type", "ai_detected"))

                event = ThreatEvent(
                    node=node,
                    severity=scan_result.get("severity", "none"),
                    attack_types=list(set(attack_types)),
                    preview=scan_result.get("input_preview", "")[:100],
                    turn=self._turn,
                )
                self._history.append(event)
                self._node_threat_count[node] = self._node_threat_count.get(node, 0) + 1

    def to_skill_context(self, agent_id: str) -> dict:
        """Return a context dict suitable for passing into AI skills."""
        with self._lock:
            prior_threats = [
                {"node": e.node, "severity": e.severity, "types": e.attack_types}
                for e in self._history
            ]
            node_hit_count = self._node_threat_count.get(agent_id, 0)
            under_attack   = len(self._history) > 0
            escalating     = len([e for e in self._history if e.severity in ("critical","high")]) >= 2

        return {
            "agent_id":        agent_id,
            "prior_threats":   prior_threats,
            "node_hit_count":  node_hit_count,
            "pipeline_under_attack": under_attack,
            "escalating_attack":     escalating,
            "turn":            self._turn,
        }

    def is_escalating(self) -> bool:
        with self._lock:
            critical_high = [e for e in self._history if e.severity in ("critical","high")]
            return len(critical_high) >= 2

    def threat_count(self) -> int:
        with self._lock:
            return len(self._history)

    def most_attacked_node(self) -> Optional[str]:
        with self._lock:
            if not self._node_threat_count:
                return None
            return max(self._node_threat_count, key=lambda k: self._node_threat_count[k])

    def summary(self) -> dict:
        with self._lock:
            return {
                "total_threats": len(self._history),
                "turns":         self._turn,
                "escalating":    self.is_escalating(),
                "node_counts":   dict(self._node_threat_count),
            }

    def reset(self) -> None:
        with self._lock:
            self._history.clear()
            self._node_threat_count.clear()
            self._turn = 0


# Global registry: one context per named graph run
_contexts: Dict[str, ThreatContext] = {}
_ctx_lock = threading.Lock()


def get_context(graph_name: str) -> ThreatContext:
    with _ctx_lock:
        if graph_name not in _contexts:
            _contexts[graph_name] = ThreatContext()
        return _contexts[graph_name]


def reset_context(graph_name: str) -> None:
    with _ctx_lock:
        if graph_name in _contexts:
            _contexts[graph_name].reset()
