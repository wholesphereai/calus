"""
Build the HarmBench input-detection benchmark for Calus.

HarmBench (Mazeika et al., "HarmBench: A Standardized Evaluation Framework for
Automated Red Teaming and Robust Refusal," CAIS / UIUC, 2024) was designed to
measure whether a *model* refuses adversarial completions. Calus is not a model;
it is an upstream gateway. So we evaluate the well-defined sub-question that maps
to Calus's role: **how many HarmBench adversarial input prompts does Calus flag
before they reach the model?**

  python -m calus.benchmark.external.harmbench.build

HarmBench's 400 behaviors split into 200 `standard` (self-contained harmful
requests), 100 `contextual` (need an external context paragraph) and 100
`copyright` (reproduce-this-text tasks). Only the 200 `standard` behaviors are
self-contained harmful-intent prompts that fall within a detection gateway's
scope, so those are the headline set. We deliberately do NOT report a single
"HarmBench score" — that phrasing implies model refusal, which is not what Calus
measures. False-positive rate is measured against the shared benign control.
"""
import logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

import os

from .._download import fetch_text
from .._benign_control import write_benign_control

HERE = os.path.dirname(__file__)

# Full HarmBench text behavior set (400 rows: 200 standard, 100 contextual,
# 100 copyright).
URL = ("https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/"
       "data/behavior_datasets/harmbench_behaviors_text_all.csv")


def build():
    import csv
    import io

    raw = fetch_text(URL, cache=os.path.join(HERE, "_behaviors_all.csv"))
    rows = list(csv.DictReader(io.StringIO(raw)))
    standard, seen = [], set()
    for r in rows:
        if r.get("FunctionalCategory") != "standard":
            continue
        line = " ".join((r.get("Behavior") or "").split())
        if line and line not in seen:
            seen.add(line)
            standard.append(line)
    return standard


def main(argv=None):
    standard = build()
    with open(os.path.join(HERE, "attacks.txt"), "w", encoding="utf-8") as f:
        f.write("# HarmBench standard behaviors (200 self-contained harmful "
                "input prompts, CAIS 2024)\n")
        f.write("\n".join(standard) + "\n")
    n_benign = write_benign_control(os.path.join(HERE, "benign.txt"))
    log.info(f"wrote {len(standard)} HarmBench standard behaviors + {n_benign} benign control")
    log.info("now run:  python -m calus.benchmark.harness --dataset harmbench")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
