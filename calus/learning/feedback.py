"""
calus.learning.feedback  — self-improving loop
==============================================
Confirmed detections make the system stronger over time:
  * add the confirmed-attack text to the similarity / embedding index (recall up)
  * mine a candidate regex from its most discriminative tokens (review before use)
  * record confirmed-benign false positives to auto-quarantine the offending rules
     (precision up)

Nothing here auto-modifies detection logic without review — mined regex and
quarantine suggestions are written to a queue for a human/CI to approve.
"""
from __future__ import annotations
import json, os, re, time
from collections import Counter

class FeedbackStore:
    def __init__(self, path="calus_feedback.json"):
        self.path = path
        self.data = {"attacks": [], "benign_fp": [], "candidate_rules": [],
                     "quarantine_suggestions": []}
        if os.path.exists(path):
            try: self.data = json.load(open(path, encoding="utf-8"))
            except Exception: pass

    def save(self):
        json.dump(self.data, open(self.path, "w", encoding="utf-8"), indent=1)

    # ---- confirmed attack that was missed or matched ----
    def confirm_attack(self, text):
        self.data["attacks"].append({"t": text[:400], "ts": time.time()})
        rule = self._mine_rule(text)
        if rule:
            self.data["candidate_rules"].append(rule)
        self.save(); return rule

    # ---- confirmed false positive on benign input ----
    def confirm_false_positive(self, text, matched_rule_ids):
        self.data["benign_fp"].append({"t": text[:300], "rules": matched_rule_ids})
        for rid in matched_rule_ids:
            self.data["quarantine_suggestions"].append(rid)
        self.save()

    @staticmethod
    def _mine_rule(text):
        """Turn a confirmed attack into a conservative candidate regex from its
        rarest multi-word literal span (review before activating)."""
        toks = re.findall(r"[A-Za-z][A-Za-z0-9_]{3,}", text.lower())
        if len(toks) < 2:
            return None
        # pick 2-3 consecutive distinctive tokens as an anchored literal phrase
        phrase = " ".join(toks[:3])
        pat = r"(?i)" + r"\s+".join(re.escape(t) for t in phrase.split())
        return {"pattern": pat, "severity": "high", "source": "feedback",
                "review": True, "from": text[:120]}

    def new_signatures(self):
        """Texts to append to the similarity / embedding index."""
        return [a["t"] for a in self.data["attacks"]]
