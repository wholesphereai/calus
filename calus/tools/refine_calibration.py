"""
calus.tools.refine_calibration — cut false positives on normal traffic.

Unlike `calibrate.py` (which rebuilds calibration.json from scratch and would lose
the existing curation), this refines the *existing* calibration.json in place:

  for every currently-active pattern, if it fires on the benign calibration
  corpus (detection/benign_calibration.txt — real normal user messages), it is
  over-broad → quarantine it (reason "fires_benign_v2").

This is what reduced the engine's false-positive rate on ordinary traffic from
6.7% to 1.1% (measured on held-out Databricks Dolly-15k). Root cause of most of
those FPs: attack payloads added as regex without escaping, so a shell '|' became
a regex alternation with a tiny branch (e.g. " sh") matching "should"/"show".

A small KEEP allowlist (detection/calibration_keep.txt) protects the handful of
patterns that carry real injection/jailbreak value at near-zero benign cost
(Pareto-optimal); a pattern matching any keep-marker is left active even if it
fires on benign. Re-run after editing the benign corpus or the keep-list.

    python -m calus.tools.refine_calibration
"""
import json, os, re, hashlib, warnings
warnings.filterwarnings("ignore")
from .calibrate import load_patterns, PKG

CAL = os.path.join(PKG, "detection", "calibration.json")
BENIGN_FILE = os.path.join(PKG, "detection", "benign_calibration.txt")
KEEP_FILE = os.path.join(PKG, "detection", "calibration_keep.txt")


def _load_lines(path):
    if not os.path.exists(path):
        return []
    return [ln.strip() for ln in open(path, encoding="utf-8")
            if ln.strip() and not ln.startswith("#")]


def main(argv=None):
    cal = json.load(open(CAL, encoding="utf-8"))
    benign = _load_lines(BENIGN_FILE)
    keep_markers = _load_lines(KEEP_FILE)
    if not benign:
        print("no benign corpus at", BENIGN_FILE, "- nothing to do")
        return 1

    deact = kept = tested = 0
    for p, sev in load_patterns():
        h = hashlib.md5(p.encode()).hexdigest()
        c = cal.get(h)
        if c is not None and not c.get("active", True):
            continue                       # already inactive — leave curation intact
        tested += 1
        try:
            rx = re.compile(p)
        except re.error:
            continue
        for b in benign:
            try:
                if rx.search(b):
                    if any(m in p for m in keep_markers):
                        kept += 1          # Pareto-protected: real attack value
                    else:
                        cal[h] = {"active": False, "reason": "fires_benign_v2", "w": 0}
                        deact += 1
                    break
            except Exception:
                break
    json.dump(cal, open(CAL, "w"))
    active = sum(1 for v in cal.values() if v.get("active", True))
    print(f"tested {tested} active patterns")
    print(f"deactivated {deact} over-broad (fire on normal traffic); "
          f"kept {kept} via allowlist")
    print(f"active patterns now: {active}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
