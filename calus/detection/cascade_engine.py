"""
calus.detection.cascade_engine — confidence-routed, self-improving detector.

Design follows the consensus of production tools (Rebuff, Vigil, LLM Guard) and
the OWASP LLM Prompt-Injection cheat sheet: a cheap->expensive cascade where each
tier only runs if the previous one was not decisive. Keeps every layer available
but does NOT run them all on every input.

    Tier 1  Deterministic  (regex + cheap anomaly signals + optional decoders)
    Tier 2  Lexical / vector similarity to known attacks
    Tier 3  Semantic classifier / embeddings  (pluggable; runs only when uncertain)
    +       Behavioral / action screening      (only with agent context)
    +       Self-improving feedback loop        (confirmed hits harden tiers 1-2)

Cross-OS, zero hard dependencies. Safe by construction: the regex tier uses the
calibrated set (ReDoS/over-broad patterns removed), an input-length cap, a
candidate cap, and a wall-clock budget, so a scan cannot hang on any OS.
"""
from __future__ import annotations
import os, re, base64, binascii, math
from dataclasses import dataclass, field

# routing thresholds (tune on your benchmark)
T1_DECISIVE = 3.0     # tier-1 score at/above this => flag now, skip deeper tiers
T1_CLEAN    = 0.6     # tier-1 score at/below this AND no anomaly => clean, stop
T2_FLAG     = 0.55    # tier-2 similarity to flag

@dataclass
class Verdict:
    flagged: bool
    confidence: float
    owasp: str = ""
    owasp_name: str = ""
    tiers_run: list = field(default_factory=list)
    reasons: list = field(default_factory=list)
    decoded_from: str = ""          # set if an obfuscation decoder fired

# ---------- cheap anomaly signals (decide whether to run decoders) ----------
_INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ue0000-\ue007f]")
def _entropy(s: str) -> float:
    if not s: return 0.0
    from collections import Counter
    c = Counter(s); n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in c.values())
def _nonascii_ratio(s: str) -> float:
    return sum(1 for ch in s if ord(ch) > 127) / len(s) if s else 0.0

# ---------- lightweight obfuscation decoders (only run on anomaly) ----------
def _try_decoders(text: str):
    """Yield (decoder_name, decoded_text) for plausible obfuscations."""
    # base64
    for m in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            d = base64.b64decode(m, validate=True).decode("utf-8", "ignore")
            if d and sum(c.isprintable() for c in d) > len(d) * 0.8:
                yield "base64", d
        except (binascii.Error, ValueError):
            pass
    # spaced-out chars: "i g n o r e"
    if re.search(r"(?:\b\w\s){4,}", text):
        yield "spaced", re.sub(r"(\w)\s(?=\w\b)", r"\1", text)
    # reversed text
    if "snoitcurtsni" in text.lower() or "erongi" in text.lower():
        yield "reversed", text[::-1]


class CascadeEngine:
    def __init__(self, patterns_root=None, embedder=None,
                 calibration_path=None, signatures_path=None):
        here = os.path.dirname(__file__)
        self.patterns_root = patterns_root or os.path.join(os.path.dirname(here), "patterns")
        self.embedder = embedder
        self._t1 = None        # scored regex engine
        self._t2 = None        # similarity layer
        self._feedback = None
        self._owasp = None
        self.ready = False
        self._calp = calibration_path
        self._sigp = signatures_path

    def prepare(self):
        from calus.detection.combined_detector import CombinedDetector
        from calus.owasp import owasp_for
        self._owasp = owasp_for
        cd = CombinedDetector(self.patterns_root,
                              calibration_path=self._calp, signatures_path=self._sigp)
        info = cd.prepare()
        self._t1 = cd.engine            # calibrated scored regex (tier 1)
        self._t2 = cd.sim               # similarity (tier 2)
        if self.embedder is not None:
            self.embedder.index_attacks(self._t2.sig_text)
        try:
            from calus.learning.feedback import FeedbackStore
            self._feedback = FeedbackStore()
        except Exception:
            self._feedback = None
        self.ready = True
        return info

    # ---------- the cascade ----------
    def scan(self, text: str, agent_context: dict | None = None) -> Verdict:
        if not self.ready:
            self.prepare()
        tiers = []; reasons = []; decoded_from = ""
        # DoS guard: extremely repetitive / low-entropy input has no real content
        # beyond a small window; truncate to bound worst-case single-core matching.
        if len(text) > 400 and _entropy(text) < 2.5:
            text = text[:200]

        # Tier 1 — deterministic regex (calibrated, capped, time-budgeted)
        t1 = self._t1.detect(text)
        tiers.append("t1_regex")
        score = t1.score
        top_cat = ""
        if t1.matched:
            top_cat = self._category_of(t1.matched)
            reasons.append(f"regex score {t1.score}")
            # surface the exact text that triggered the top match (the "where")
            snip = next((m[4] for m in t1.matched if len(m) > 4 and m[4]), "")
            if snip:
                reasons.append(f'matched text: "{snip}"')

        # Conditional decoders — only on real obfuscation signals
        has_b64 = re.search(r"[A-Za-z0-9+/]{20,}={0,2}", text) is not None
        spaced  = re.search(r"(?:\b\w\b[ \t]){5,}", text) is not None
        if (_INVISIBLE.search(text) or _nonascii_ratio(text) > 0.30 or has_b64 or spaced):
            tiers.append("decoders")
            for name, decoded in _try_decoders(text):
                d1 = self._t1.detect(decoded)
                if d1.score > score:
                    score = d1.score; decoded_from = name
                    reasons.append(f"obfuscation '{name}' decoded -> regex score {d1.score}")
                    if d1.matched: top_cat = self._category_of(d1.matched)

        # Route: decisive malicious -> stop, skip deeper tiers
        if score >= T1_DECISIVE:
            return self._verdict(True, min(score / (T1_DECISIVE * 2), 1.0), top_cat,
                                 tiers, reasons, decoded_from, agent_context)

        # Otherwise ALWAYS consult Tier 2 (cheap lexical/vector similarity).
        # This is what catches paraphrases and learned signatures that regex misses.
        tiers.append("t2_similarity")
        sim = self._t2.detect(text)
        if sim["flagged"] or sim["similarity"] >= T2_FLAG:
            reasons.append(f"similar to known attack ({sim['similarity']})")
            return self._verdict(True, max(score / (T1_DECISIVE * 2), sim["similarity"]),
                                 top_cat, tiers, reasons, decoded_from, agent_context)

        # Tier 3 — semantic classifier / embeddings (only if plugged in)
        if self.embedder is not None:
            tiers.append("t3_semantic")
            em = self.embedder.detect(text)
            if em["flagged"]:
                reasons.append(f"semantic match ({em['similarity']})")
                return self._verdict(True, em["similarity"], top_cat, tiers, reasons,
                                     decoded_from, agent_context)

        # gray-zone, nothing decisive -> not flagged (tune thresholds to taste)
        conf = max(score / (T1_DECISIVE * 2), sim["similarity"])
        return self._verdict(conf >= 0.5, conf, top_cat, tiers, reasons, decoded_from, agent_context)

    # ---------- behavioral / action screening (agent context) ----------
    def _verdict(self, flagged, conf, cat, tiers, reasons, decoded_from, ctx):
        if ctx:
            b = self._behavioral(ctx)
            if b:
                tiers.append("behavioral"); reasons.extend(b)
                flagged = True; conf = max(conf, 0.7)
        code, name = self._owasp(cat) if self._owasp else (None, "")
        return Verdict(flagged, round(conf, 3), code or "", name,
                       tiers, reasons, decoded_from)

    @staticmethod
    def _behavioral(ctx):
        out = []
        tools = ctx.get("tool_calls", [])
        if len(tools) > ctx.get("max_tools", 8):
            out.append(f"excessive agency: {len(tools)} tool calls")
        for t in tools:
            n = str(t).lower()
            if any(k in n for k in ("delete", "drop", "rm -rf", "exfiltrat", "sendmail", "http")):
                out.append(f"high-risk tool action: {str(t)[:40]}")
        if ctx.get("writes_memory") and ctx.get("from_untrusted"):
            out.append("possible memory poisoning (untrusted -> memory write)")
        return out

    @staticmethod
    def _category_of(matched):
        # `matched` is weight-sorted [(rule_id, severity, weight, category), ...].
        # Take the highest-weight matched rule that actually carries a category
        # (many rules have an empty category); that drives the OWASP mapping.
        for m in matched or []:
            cat = m[3] if len(m) > 3 else ""
            if cat:
                return cat
        return ""

    # ---------- self-improving loop ----------
    def learn(self, text: str, is_attack: bool, matched_rule_ids=None):
        """Feed a confirmed verdict back in. Attacks harden tier-2 (and queue a
        candidate rule); confirmed false positives queue rules for quarantine."""
        if self._feedback is None:
            from calus.learning.feedback import FeedbackStore
            self._feedback = FeedbackStore()
        if is_attack:
            self._feedback.confirm_attack(text)
            # immediately add to the live similarity index (recall up now)
            try:
                from calus.detection.similarity_layer import _toks
                self._t2.sig_text.append(text[:300])
                self._t2.sig_tokens.append(_toks(text))
                for tk in _toks(text):
                    self._t2.inverted.setdefault(tk, []).append(len(self._t2.sig_text) - 1)
            except Exception:
                pass
        else:
            self._feedback.confirm_false_positive(text, matched_rule_ids or [])
        return True
