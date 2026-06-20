"""
calus.detection.similarity_layer  (Tier 2)
==========================================
Lexical near-duplicate / paraphrase detection over the known-attack corpus.

Regex (Tier 1) only catches attacks whose exact tokens it encoded. This layer
flags inputs that are *similar* to a known attack even when worded differently,
using token Jaccard similarity with an inverted index for speed. Pure Python,
no dependencies, no regex execution (so it cannot ReDoS-hang).

For production-grade paraphrase/translation robustness, swap the token-Jaccard
scorer for sentence embeddings + ANN (FAISS/HNSW) behind the same interface.
"""
from __future__ import annotations
import json, os, re

def _norm(s): return re.sub(r"\s+", " ", s.lower()).strip()
def _toks(s): return {t for t in re.findall(r"[a-z0-9]+", _norm(s)) if len(t) >= 3}

class SimilarityLayer:
    def __init__(self, index_path=None, threshold=0.45):
        self.threshold = threshold
        self.sig_tokens = []      # list[set]
        self.sig_text = []        # list[str]
        self.inverted = {}        # token -> [sig ids]
        if index_path is None:
            index_path = os.path.join(os.path.dirname(__file__), "attack_signatures.json")
        if os.path.exists(index_path):
            self.load(index_path)

    def load(self, path):
        data = json.load(open(path, encoding="utf-8"))
        self.sig_tokens = [set(s["tokens"]) for s in data["signatures"]]
        self.sig_text = [s["text"] for s in data["signatures"]]
        self.inverted = data["inverted"]

    def score(self, text):
        """Return (max_similarity, best_signature_text)."""
        q = _toks(text)
        if not q:
            return 0.0, ""
        # candidate signatures = those sharing at least one query token
        cand = set()
        for t in q:
            cand.update(self.inverted.get(t, []))
        best = 0.0; best_txt = ""
        for i in cand:
            st = self.sig_tokens[i]
            inter = len(q & st)
            if not inter:
                continue
            jac = inter / len(q | st)
            if jac > best:
                best, best_txt = jac, self.sig_text[i]
        return best, best_txt

    def detect(self, text):
        sim, sig = self.score(text)
        return {"flagged": sim >= self.threshold,
                "similarity": round(sim, 3),
                "nearest_attack": sig[:120]}
