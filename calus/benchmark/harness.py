"""
calus.benchmark.harness — measure the real cascade engine's accuracy.

    python -m calus.benchmark.harness                       # uses bundled datasets
    python -m calus.benchmark.harness --dataset agentdojo   # held-out AgentDojo set
    python -m calus.benchmark.harness --dataset injecagent  # ACL 2024, all splits
    python -m calus.benchmark.harness --dataset jailbreakbench
    python -m calus.benchmark.harness --dataset advbench
    python -m calus.benchmark.harness --dataset harmbench
    python -m calus.benchmark.harness --attacks a.txt --benign b.txt

Each dataset is one input per line. It scans every line through the real engine
(calus.scan), then reports precision / recall / F1 at the engine's default
verdict AND at the confidence >= 0.20 operating point. Use `--sweep` for the full
threshold sweep.

IMPORTANT for a trustworthy number: use attacks the patterns were NOT built from
and genuinely benign text. The external/* sets are held-out third-party
benchmarks; the bundled datasets are a smoke benchmark, not proof.
"""
import logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

import argparse
import os
import time

HERE = os.path.dirname(__file__)
EXT = os.path.join(HERE, "external")


def load(path):
    return [ln.strip() for ln in open(path, encoding="utf-8", errors="ignore")
            if ln.strip() and not ln.startswith("#")]


def prf(tp, fp, fn):
    rec = tp / (tp + fn) if tp + fn else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return rec, prec, f1


def _ext(name, *parts):
    return os.path.join(EXT, name, *parts)


# A dataset maps to one or more labelled (attacks, benign) splits. Multi-split
# datasets (InjecAgent) print one report per split.
def _splits_for(dataset):
    if dataset == "agentdojo":
        return [("AgentDojo", _ext("agentdojo", "attacks.txt"),
                 _ext("agentdojo", "benign.txt"))]
    if dataset == "advbench":
        return [("AdvBench (520 harmful)", _ext("advbench", "attacks.txt"),
                 _ext("advbench", "benign.txt"))]
    if dataset == "jailbreakbench":
        ben = _ext("jailbreakbench", "benign.txt")
        return [
            ("JBB — jailbreak artifacts (all families)",
             _ext("jailbreakbench", "artifacts_all.txt"), ben),
            ("JBB — JBC manual templates",
             _ext("jailbreakbench", "artifacts_jbc.txt"), ben),
            ("JBB — PAIR adaptive jailbreaks",
             _ext("jailbreakbench", "artifacts_pair.txt"), ben),
            ("JBB — GCG adversarial suffix",
             _ext("jailbreakbench", "artifacts_gcg.txt"), ben),
            ("JBB — bare behavior goals (intent control)",
             _ext("jailbreakbench", "attacks.txt"), ben),
        ]
    if dataset == "harmbench":
        return [("HarmBench (200 standard, input detection)",
                 _ext("harmbench", "attacks.txt"), _ext("harmbench", "benign.txt"))]
    if dataset == "injecagent":
        return [
            ("InjecAgent — Standard", _ext("injecagent", "attacks_standard.txt"),
             _ext("injecagent", "benign_standard.txt")),
            ("InjecAgent — Enhanced", _ext("injecagent", "attacks_enhanced.txt"),
             _ext("injecagent", "benign_enhanced.txt")),
            ("InjecAgent — Direct Harm", _ext("injecagent", "attacks_direct_harm.txt"),
             _ext("injecagent", "benign_direct_harm.txt")),
            ("InjecAgent — Data Exfiltration", _ext("injecagent", "attacks_data_exfil.txt"),
             _ext("injecagent", "benign_data_exfil.txt")),
        ]
    return None


def score(det, attacks_path, benign_path, sweep=False):
    attacks = load(attacks_path)
    benign = load(benign_path)

    def scan_all(items):
        return [(r.flagged, r.confidence) for r in (det.scan(s) for s in items)]

    t0 = time.time()
    A = scan_all(attacks)
    B = scan_all(benign)
    dt = time.time() - t0
    n = len(attacks) + len(benign)
    ms = dt / n * 1000 if n else 0.0

    TP = sum(1 for f, _ in A if f)
    FP = sum(1 for f, _ in B if f)
    FN = len(A) - TP
    rec, prec, f1 = prf(TP, FP, FN)
    log.info(f"  scanned {n} inputs in {dt:.1f}s ({ms:.1f} ms/scan)")
    log.info(f"  DEFAULT verdict      recall={rec*100:5.1f}%  precision={prec*100:5.1f}%"
          f"  F1={f1*100:5.1f}%   (TP={TP} FP={FP} FN={FN}, n_attack={len(A)} n_benign={len(B)})")

    # Fixed 0.20 operating point (the point reported for AgentDojo in the README).
    TP2 = sum(1 for _, c in A if c >= 0.20)
    FP2 = sum(1 for _, c in B if c >= 0.20)
    FN2 = len(A) - TP2
    r2, p2, f2 = prf(TP2, FP2, FN2)
    log.info(f"  confidence >= 0.20   recall={r2*100:5.1f}%  precision={p2*100:5.1f}%"
          f"  F1={f2*100:5.1f}%   (TP={TP2} FP={FP2} FN={FN2})")

    if sweep:
        log.info(f"  {'thresh':>9} {'recall':>8} {'precision':>10} {'F1':>7} {'FP':>10}")
        for t in [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]:
            tp = sum(1 for _, c in A if c >= t)
            fp = sum(1 for _, c in B if c >= t)
            fn = len(A) - tp
            rr, pp, ff = prf(tp, fp, fn)
            log.info(f"  {t:>9.2f} {rr*100:>7.1f}% {pp*100:>9.1f}% {ff*100:>6.1f}% {fp:>6}/{len(B)}")
    return {"recall": rec, "precision": prec, "f1": f1,
            "recall20": r2, "precision20": p2, "f1_20": f2,
            "fp": FP, "n_benign": len(B), "n_attack": len(A)}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset",
                    choices=["bundled", "agentdojo", "injecagent",
                             "jailbreakbench", "advbench", "harmbench"],
                    default="bundled")
    ap.add_argument("--attacks", default=None)
    ap.add_argument("--benign", default=None)
    ap.add_argument("--sweep", action="store_true", help="sweep confidence thresholds")
    a = ap.parse_args(argv)

    import calus
    log.info("loading engine ...")
    det = calus.get_detector()

    # Explicit file pair overrides the dataset registry.
    if a.attacks or a.benign:
        a.attacks = a.attacks or os.path.join(HERE, "datasets", "attacks.txt")
        a.benign = a.benign or os.path.join(HERE, "datasets", "benign.txt")
        log.info(f"\n# custom: {a.attacks} vs {a.benign}")
        score(det, a.attacks, a.benign, sweep=a.sweep)
        return 0

    if a.dataset == "bundled":
        log.info("\n# bundled smoke set")
        score(det, os.path.join(HERE, "datasets", "attacks.txt"),
              os.path.join(HERE, "datasets", "benign.txt"), sweep=a.sweep)
        return 0

    splits = _splits_for(a.dataset)
    for label, atk, ben in splits:
        if not (os.path.exists(atk) and os.path.exists(ben)):
            log.info(f"\n# {label}: MISSING test files — run the dataset's build.py first")
            continue
        log.info(f"\n# {label}")
        score(det, atk, ben, sweep=a.sweep)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
