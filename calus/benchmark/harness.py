"""
calus.benchmark.harness — measure the real cascade engine's accuracy.

    python -m calus.benchmark.harness                       # uses bundled datasets
    python -m calus.benchmark.harness --attacks a.txt --benign b.txt

Each dataset is one input per line. It scans every line through the real engine
(calus.scan), then reports precision / recall / F1 at the engine's default
verdict AND sweeps the confidence threshold so you can pick an operating point.

IMPORTANT for a trustworthy number: use attacks the patterns were NOT built from
and genuinely benign text. The bundled datasets are a smoke benchmark, not proof.
"""
import argparse, os, sys, time

def load(path):
    return [ln.strip() for ln in open(path, encoding="utf-8", errors="ignore")
            if ln.strip() and not ln.startswith("#")]

def prf(tp, fp, fn):
    rec = tp / (tp + fn) if tp + fn else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return rec, prec, f1

def main(argv=None):
    here = os.path.dirname(__file__)
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", choices=["bundled", "agentdojo"], default="bundled",
                    help="bundled smoke set, or the held-out AgentDojo set")
    ap.add_argument("--attacks", default=None)
    ap.add_argument("--benign",  default=None)
    ap.add_argument("--sweep", action="store_true", help="sweep confidence thresholds")
    a = ap.parse_args(argv)

    if a.dataset == "agentdojo":
        base = os.path.join(here, "external", "agentdojo")
        a.attacks = a.attacks or os.path.join(base, "attacks.txt")
        a.benign  = a.benign  or os.path.join(base, "benign.txt")
        print("dataset: AgentDojo (held-out, external)")
    a.attacks = a.attacks or os.path.join(here, "datasets", "attacks.txt")
    a.benign  = a.benign  or os.path.join(here, "datasets", "benign.txt")
    import calus
    attacks = load(a.attacks); benign = load(a.benign)
    print(f"loading engine + scanning {len(attacks)} attacks + {len(benign)} benign ...")
    t0 = time.time()
    det = calus.get_detector()

    def scan_all(items):
        out = []
        for s in items:
            r = det.scan(s)
            out.append((r.flagged, r.confidence))
        return out
    A = scan_all(attacks); B = scan_all(benign)
    dt = time.time() - t0
    n = len(attacks) + len(benign)
    print(f"scanned {n} inputs in {dt:.1f}s ({dt/n*1000:.1f} ms/scan)\n")

    # default verdict
    TP = sum(1 for f, _ in A if f); FP = sum(1 for f, _ in B if f); FN = len(A) - TP
    rec, prec, f1 = prf(TP, FP, FN)
    print("=== DEFAULT verdict (engine thresholds) ===")
    print(f"  recall={rec*100:5.1f}%  precision={prec*100:5.1f}%  F1={f1*100:5.1f}%"
          f"  (TP={TP} FP={FP} FN={FN})")

    if a.sweep or True:
        print("\n=== CONFIDENCE SWEEP (flag if confidence >= t) ===")
        print(f"  {'thresh':>7} {'recall':>8} {'precision':>10} {'F1':>7} {'FP':>8}")
        best = None
        for t in [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]:
            TP = sum(1 for _, c in A if c >= t); FP = sum(1 for _, c in B if c >= t)
            FN = len(A) - TP
            rec, prec, f1 = prf(TP, FP, FN)
            print(f"  {t:>7.2f} {rec*100:>7.1f}% {prec*100:>9.1f}% {f1*100:>6.1f}% {FP:>4}/{len(B)}")
            if best is None or f1 > best[1]: best = (t, f1, rec, prec)
        print(f"\n  best F1 at confidence>={best[0]:.2f}: "
              f"F1={best[1]*100:.1f}% recall={best[2]*100:.1f}% precision={best[3]*100:.1f}%")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
