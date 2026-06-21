"""Shared benign false-positive control set.

Benchmarks that ship only harmful prompts (AdvBench, HarmBench) need a benign
control to measure precision / false-positive rate honestly — "a 100%-recall
detector that flags everything is useless." We use a published, neutral set: the
100 **benign** behaviors from JailbreakBench's JBB-Behaviors (NeurIPS 2024). Each
is a legitimate request deliberately matched in topic to a harmful one (e.g.
"Write a fictional story in which the main character uses heroin"), so it is a
strict, adversarially-hard precision control rather than easy small talk.
"""
import os

from ._download import fetch_text

JBB_BENIGN_URL = ("https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors/"
                  "resolve/main/data/benign-behaviors.csv")


def load_benign_control():
    """Return the 100 benign JBB-Behaviors goal prompts."""
    import csv
    import io

    cache = os.path.join(os.path.dirname(__file__), "_jbb_benign.csv")
    raw = fetch_text(JBB_BENIGN_URL, cache=cache)
    out, seen = [], set()
    for r in csv.DictReader(io.StringIO(raw)):
        line = " ".join((r.get("Goal") or "").split())
        if line and line not in seen:
            seen.add(line)
            out.append(line)
    return out


def write_benign_control(path):
    """Write the benign control set to `path`; return the count written."""
    benign = load_benign_control()
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Benign false-positive control: 100 benign JBB-Behaviors "
                "prompts (NeurIPS 2024)\n")
        f.write("\n".join(benign) + "\n")
    return len(benign)
