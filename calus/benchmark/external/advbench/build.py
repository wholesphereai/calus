"""
Build the AdvBench detection benchmark for Calus.

AdvBench (Zou, Wang, Kolter, Fredrikson, "Universal and Transferable Adversarial
Attacks on Aligned Language Models," arXiv 2307.15043, 2023) is the most-cited
harmful-prompt corpus in the jailbreak literature: 520 direct harmful requests
spanning misinformation, illegal activity, hate speech, computer crime, fraud and
more. Calus is an upstream detector, so the question is: **how many of these
harmful inputs does Calus flag before they reach the model?**

This script materializes the test set the harness consumes.

  python -m calus.benchmark.external.advbench.build

It downloads the official `harmful_behaviors.csv` (520 rows, `goal`/`target`
columns) and writes `attacks.txt` (one harmful goal per line). AdvBench ships no
benign split, so precision/false-positive rate is measured against a shared,
published benign control set — the 100 genuinely-benign JBB-Behaviors prompts
(see `external/_benign_control.py`) — which the harness loads automatically.
"""
import os

from .._download import fetch_text
from .._benign_control import write_benign_control

HERE = os.path.dirname(__file__)

# Official AdvBench harmful_behaviors.csv (520 rows).
URL = ("https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/"
       "data/advbench/harmful_behaviors.csv")


def build():
    import csv
    import io

    raw = fetch_text(URL, cache=os.path.join(HERE, "_harmful_behaviors.csv"))
    rows = list(csv.DictReader(io.StringIO(raw)))
    goals = []
    seen = set()
    for r in rows:
        line = " ".join((r.get("goal") or "").split())
        if line and line not in seen:
            seen.add(line)
            goals.append(line)
    return goals


def main(argv=None):
    goals = build()
    with open(os.path.join(HERE, "attacks.txt"), "w", encoding="utf-8") as f:
        f.write("# AdvBench harmful behaviors (520 direct harmful goals, "
                "arXiv 2307.15043)\n")
        f.write("\n".join(goals) + "\n")
    n_benign = write_benign_control(os.path.join(HERE, "benign.txt"))
    print(f"wrote {len(goals)} AdvBench harmful goals + {n_benign} benign control")
    print("now run:  python -m calus.benchmark.harness --dataset advbench")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
