"""
calus.detection.scored_engine
=============================
Accuracy-first detection engine.

The flat "match ANY of N regex" approach has ~100% recall but ~9% precision:
with tens of thousands of low-specificity patterns, *something* always fires,
so almost every input is flagged. This engine fixes that with four mechanisms:

  1. Calibration   - patterns that fire on a benign control set are quarantined
                     (these over-broad signatures cause the false positives).
  2. Weighting     - each pattern contributes a weight (severity x specificity),
                     not a boolean. One weak keyword hit is not an attack.
  3. Scoring       - an input is flagged only if its summed weight >= threshold.
                     The threshold is the precision/recall knob you tune.
  4. ReDoS guard   - patterns are profiled once against an adversarial probe;
                     catastrophic-backtracking patterns are quarantined so a
                     single crafted input cannot hang the scanner.

A literal pre-filter (Aho-Corasick-style) keeps it fast: only patterns whose
required literal appears in the input are evaluated.

No third-party dependencies. Optional fast backends (google-re2, hyperscan)
can be plugged into `_compile` for production throughput.
"""
from __future__ import annotations
import re, time, json, os, warnings, hashlib
from dataclasses import dataclass, field

SEVERITY_WEIGHT = {"critical": 3.0, "high": 2.0, "medium": 1.0,
                   "warning": 0.5, "low": 0.5, "info": 0.25}

# ---- benign control set used for calibration (extend with your own data) ----
DEFAULT_BENIGN = [
    "The weather today is sunny with a high of 75 degrees.",
    "Please summarize the attached report and send it by Friday.",
    "def add(a, b):\n    return a + b",
    "import pandas as pd\ndf = pd.read_csv('sales.csv')",
    "Ignore the background noise in the recording when transcribing.",
    "Run the unit tests and tell me if anything fails.",
    "Configure the git remote to push to the main branch.",
    "Execute the quarterly plan and report progress next week.",
    "Act as a friendly tour guide for my trip to Rome.",
    "The agent will call the customer back within 24 hours.",
]

# adversarial probe to surface catastrophic backtracking during profiling
REDOS_PROBE = ("a" * 40 + "!" * 40 + " " + "x," * 40 + "\\" * 20)

# sentinel for a rule whose pattern fails to compile — never matches anything
_NEVER = re.compile(r"(?!)")


@dataclass
class Rule:
    pattern: str
    severity: str = "medium"
    rule_id: str = ""
    category: str = ""
    regex: "re.Pattern" = None
    weight: float = 1.0
    quarantined: bool = False
    quarantine_reason: str = ""


@dataclass
class Detection:
    flagged: bool
    score: float
    threshold: float
    matched: list = field(default_factory=list)   # [(rule_id, severity, weight, category)]


class ScoredEngine:
    def __init__(self, threshold: float = 3.0, benign_corpus=None,
                 redos_budget_ms: float = 25.0, cache_path: str | None = None):
        self.threshold = threshold
        self.benign = list(benign_corpus or DEFAULT_BENIGN)
        self.redos_budget = redos_budget_ms / 1000.0
        self.cache_path = cache_path
        self.rules: list[Rule] = []
        self._index: dict[str, list[int]] = {}     # literal anchor -> rule indices
        self._always: list[int] = []               # rules with no safe anchor
        self._scanners: list[re.Pattern] = []       # chunked literal scanners

    # ---------- loading ----------
    def add_rule(self, pattern, severity="medium", rule_id="", category=""):
        # Regexes are compiled LAZILY (see _compiled) on first use, not here —
        # eagerly compiling ~28k patterns dominated startup (~20s). Each scan only
        # touches a small candidate subset, so compilation amortizes across scans.
        spec = self._specificity(pattern)
        w = SEVERITY_WEIGHT.get(str(severity).lower(), 1.0) * spec
        self.rules.append(Rule(pattern, str(severity).lower(), rule_id, category, None, w))
        return True

    def _compiled(self, r):
        """Compile a rule's regex on first use and cache it. An uncompilable
        pattern is cached as a never-match sentinel so it isn't retried."""
        rx = r.regex
        if rx is None:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")      # nested-set FutureWarnings handled in calibration
                try:
                    rx = re.compile(r.pattern)
                except re.error:
                    rx = _NEVER
            r.regex = rx
        return rx

    @staticmethod
    def _specificity(pattern: str) -> float:
        """Longer required literals => more specific => higher weight (0.25..1.5)."""
        body = re.sub(r'^\(\?[a-z]+\)', '', pattern)
        tmp = re.sub(r'\\.', '\x00', body)
        tmp = re.sub(r'\[[^\]]*\]', '\x00', tmp)
        runs = re.findall(r'[A-Za-z0-9_]{3,}', tmp)
        longest = max((len(r) for r in runs), default=0)
        if longest >= 10: return 1.5
        if longest >= 6:  return 1.0
        if longest >= 4:  return 0.6
        return 0.25                                  # short/no literal => weak evidence

    # ---------- calibration & ReDoS profiling ----------
    def calibrate(self):
        """Quarantine over-broad patterns (fire on benign) and ReDoS patterns."""
        # ReDoS: time each pattern against an adversarial probe
        for r in self.rules:
            t0 = time.perf_counter()
            try:
                self._compiled(r).search(REDOS_PROBE)
            except Exception:
                pass
            if time.perf_counter() - t0 > self.redos_budget:
                r.quarantined = True; r.quarantine_reason = "redos"
        # over-broad: fire on benign control text or match the empty string
        for r in self.rules:
            if r.quarantined:
                continue
            try:
                if self._compiled(r).search(""):
                    r.quarantined = True; r.quarantine_reason = "matches_empty"; continue
                for b in self.benign:
                    if self._compiled(r).search(b):
                        r.quarantined = True; r.quarantine_reason = "fires_on_benign"; break
            except Exception:
                r.quarantined = True; r.quarantine_reason = "error"
        self._build_index()
        return self.calibration_report()

    def calibration_report(self):
        from collections import Counter
        c = Counter(r.quarantine_reason for r in self.rules if r.quarantined)
        return {"total": len(self.rules),
                "active": sum(1 for r in self.rules if not r.quarantined),
                "quarantined": dict(c)}

    # ---------- literal pre-filter ----------
    @staticmethod
    def _top_level_alt(s):
        depth = 0; i = 0
        while i < len(s):
            c = s[i]
            if c == '\\': i += 2; continue
            if c == '[':
                j = s.find(']', i + 1); i = (j + 1) if j > 0 else i + 1; continue
            if c == '(': depth += 1
            elif c == ')': depth -= 1
            elif c == '|' and depth == 0: return True
            i += 1
        return False

    def _anchor(self, pattern):
        a = self._anchors(pattern)
        return a[0] if a else None

    def _anchors(self, pattern):
        """Return a list of literal anchors. A candidate must contain at least
        one. Handles alternation: if the only literals are inside (a|b|c) groups,
        anchor under every branch so the pattern is not missed."""
        body = re.sub(r'^\(\?[a-z]+\)', '', pattern)
        if self._top_level_alt(body):
            return None
        blanked = re.sub(r'\\.', '\x00', body)
        blanked = re.sub(r'\[[^\]]*\]', '\x00', blanked)
        # required literals = those NOT inside an alternation group
        required = re.sub(r'\((?:\?:)?[^()]*\|[^()]*\)', '\x00', blanked)
        req = re.findall(r'[A-Za-z][A-Za-z0-9_]{4,}', required)
        if req:
            return [max(req, key=len).lower()]
        # else: anchor on the branches of the first all-literal alternation group
        for g in re.findall(r'\((?:\?:)?([^()]*\|[^()]*)\)', blanked):
            branches = g.split('|')
            reps = []
            ok = True
            for b in branches:
                lits = re.findall(r'[A-Za-z][A-Za-z0-9_]{2,}', b)
                if not lits:
                    ok = False; break
                reps.append(min(lits, key=len).lower())
            if ok and reps and all(len(x) >= 3 for x in reps):
                return list(dict.fromkeys(reps))
        return None

    def _build_index(self):
        self._index.clear(); self._always.clear()
        for i, r in enumerate(self.rules):
            if r.quarantined:
                continue
            anchors = self._anchors(r.pattern)
            if anchors:
                for a in anchors:
                    self._index.setdefault(a, []).append(i)
            elif r.weight >= 0.6:          # keep only specific no-anchor patterns in always-run
                self._always.append(i)
        anchors = sorted(self._index.keys(), key=len, reverse=True)
        self._scanners = [re.compile('|'.join(re.escape(w) for w in anchors[k:k + 1500]))
                          for k in range(0, len(anchors), 1500)]

    def _candidates(self, text):
        low = text.lower()
        idx = set(self._always)
        for sc in self._scanners:
            for m in sc.finditer(low):
                idx.update(self._index[m.group(0)])
        return idx

    # ---------- scoring ----------
    def detect(self, text, threshold=None, max_len=2000, time_budget_ms=750) -> Detection:
        thr = self.threshold if threshold is None else threshold
        text = text[:max_len]                          # cap input -> bounds backtracking
        score = 0.0; matched = []
        deadline = time.perf_counter() + time_budget_ms / 1000.0
        cand = self._candidates(text)
        if len(cand) > 4000:                       # bound work: evaluate highest-weight first
            cand = sorted(cand, key=lambda j: -self.rules[j].weight)[:4000]
        for n, i in enumerate(cand):
            if (n & 63) == 0 and time.perf_counter() > deadline:
                break                                  # hard time budget -> never hang the caller
            r = self.rules[i]
            try:
                if self._compiled(r).search(text):
                    score += r.weight
                    matched.append((r.rule_id or r.pattern[:40], r.severity, r.weight, r.category))
            except Exception:
                continue
        matched.sort(key=lambda x: -x[2])
        return Detection(score >= thr, round(score, 2), thr, matched)


def build_from_package(patterns_root, skip_hashes=None, **kw):
    """Load every rule (dict + tuple form) from a calus patterns/ tree."""
    import ast
    eng = ScoredEngine(**kw); skipped = 0
    skip_hashes = skip_hashes or set()
    def _skip(p): return hashlib.md5(p.encode()).hexdigest() in skip_hashes
    for dp, _, fs in os.walk(patterns_root):
        for fn in fs:
            if not fn.endswith(".py"):
                continue
            try:
                tree = ast.parse(open(os.path.join(dp, fn), encoding="utf-8").read())
            except Exception:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Dict):
                    try: d = ast.literal_eval(node)
                    except Exception: continue
                    if isinstance(d, dict) and "patterns" in d:
                        sev = d.get("severity", "medium"); rid = str(d.get("id", "")); cat = d.get("category", "")
                        pats = d["patterns"]
                        for p in (pats if isinstance(pats, (list, tuple)) else [pats]):
                            if isinstance(p, str) and not _skip(p) and not eng.add_rule(p, sev, rid, cat):
                                skipped += 1
                elif isinstance(node, ast.Assign) and isinstance(node.value, (ast.List, ast.Tuple)):
                    try: val = ast.literal_eval(node.value)
                    except Exception: continue
                    if isinstance(val, (list, tuple)):
                        for el in val:
                            if isinstance(el, (tuple, list)) and el and isinstance(el[0], str):
                                sev = el[1] if len(el) > 1 else "medium"
                                if not _skip(el[0]) and not eng.add_rule(el[0], sev):
                                    skipped += 1
    eng.uncompilable = skipped
    return eng
