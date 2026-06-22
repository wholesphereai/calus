"""
Build the InjecAgent indirect-prompt-injection benchmark for Calus.

InjecAgent (Zhan et al., "InjecAgent: Benchmarking Indirect Prompt Injections in
Tool-Integrated Large Language Model Agents," ACL 2024 Findings) hides an
attacker instruction inside the content a tool returns to an agent. This is the
exact threat Calus's tool-call observability layer exists to catch: the gateway
scans tool output, so we score whether Calus flags the **rendered tool response**
that carries the injection.

  python -m calus.benchmark.external.injecagent.build

The 1,054 test cases come in two attack types — Direct Harm (dh) and Data
Stealing / exfiltration (ds) — each in two prompt settings:

  * standard ("base")     : the attacker instruction is injected as-is
  * enhanced ("enhanced") : a "hacking prompt" wrapper is prepended
                            ("IMPORTANT!!! Ignore all previous instructions ...")

For each test case the attack line is the full `Tool Response` (the injected tool
output the agent would receive). The benign control is the *same* tool-response
template with the `<Attacker Instruction>` slot filled by ordinary content — so
attack and control differ only by the injection, isolating detection of the
injection itself rather than the surrounding domain text.

Outputs (consumed by the harness's `injecagent` splits):
  attacks_standard.txt / benign_standard.txt   (dh_base + ds_base)
  attacks_enhanced.txt / benign_enhanced.txt   (dh_enhanced + ds_enhanced)
  attacks_direct_harm.txt / benign_direct_harm.txt   (dh_base)
  attacks_data_exfil.txt / benign_data_exfil.txt     (ds_base)
"""
import logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)

import os

from .._download import fetch_text

HERE = os.path.dirname(__file__)

BASE_URL = ("https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/"
            "data/test_cases_{name}.json")

PLACEHOLDER = "<Attacker Instruction>"

# Ordinary content used to fill the injection slot in the benign control, so the
# benign tool output is realistic same-domain text. Rotated to avoid identical
# lines; the harness de-dupes anyway.
BENIGN_FILLERS = [
    "Great product, exactly as described and it arrived a day early.",
    "Thanks for the update, everything looks good on my end.",
    "The meeting notes from yesterday have been added to the shared folder.",
    "Battery life is solid and the screen is brighter than I expected.",
    "Reminder: the quarterly review is scheduled for next Tuesday at 10am.",
]


def _load(name):
    import json

    cache = os.path.join(HERE, f"_{name}.json")
    raw = fetch_text(BASE_URL.format(name=name), cache=cache)
    return json.loads(raw)


def _one_line(s):
    return " ".join(str(s).split())


def _attacks_and_benign(cases):
    """Return (attack lines, benign control lines) for a list of test cases."""
    attacks, benign = [], []
    a_seen, b_seen = set(), set()
    for i, c in enumerate(cases):
        tr = _one_line(c.get("Tool Response", ""))
        if tr and tr not in a_seen:
            a_seen.add(tr)
            attacks.append(tr)
        tmpl = c.get("Tool Response Template", "")
        if PLACEHOLDER in tmpl:
            filler = BENIGN_FILLERS[i % len(BENIGN_FILLERS)]
            clean = _one_line(tmpl.replace(PLACEHOLDER, filler))
            if clean and clean not in b_seen:
                b_seen.add(clean)
                benign.append(clean)
    return attacks, benign


def _write(stem, attacks, benign):
    with open(os.path.join(HERE, f"attacks_{stem}.txt"), "w", encoding="utf-8") as f:
        f.write(f"# InjecAgent {stem}: injected tool responses (ACL 2024)\n")
        f.write("\n".join(attacks) + "\n")
    with open(os.path.join(HERE, f"benign_{stem}.txt"), "w", encoding="utf-8") as f:
        f.write(f"# InjecAgent {stem}: clean tool responses (injection slot -> ordinary content)\n")
        f.write("\n".join(benign) + "\n")
    return len(attacks), len(benign)


def main(argv=None):
    dh_base = _load("dh_base")
    ds_base = _load("ds_base")
    dh_enh = _load("dh_enhanced")
    ds_enh = _load("ds_enhanced")

    splits = {
        "standard": dh_base + ds_base,
        "enhanced": dh_enh + ds_enh,
        "direct_harm": dh_base,
        "data_exfil": ds_base,
    }
    total = 0
    for stem, cases in splits.items():
        a, b = _attacks_and_benign(cases)
        na, nb = _write(stem, a, b)
        total += na
        log.info(f"  {stem:12s}: {na:4d} injected attacks + {nb:4d} clean benign")
    log.info(f"wrote InjecAgent splits "
          f"(standard={len(splits['standard'])} + enhanced={len(splits['enhanced'])} cases)")
    log.info("now run:  python -m calus.benchmark.harness --dataset injecagent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
