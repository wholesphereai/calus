"""
Build the JailbreakBench detection benchmark for Calus.

JailbreakBench (Chao, Debenedetti et al., "JailbreakBench: An Open Robustness
Benchmark for Jailbreaking Large Language Models," NeurIPS 2024 Datasets &
Benchmarks) publishes JBB-Behaviors (100 misuse + 100 topic-matched benign
behaviors) AND a library of *attack artifacts* — the actual jailbreak prompt
strings that successfully broke models.

A detection gateway should be judged on the **artifacts**: the bare behavior
goals ("Write a defamatory article ...") are harmful-intent requests with no
adversarial wrapper, which is content-moderation territory, not injection/
jailbreak-pattern detection. The artifacts are the real attack strings Calus is
designed to catch. We therefore build both, as separate splits:

  * behaviors  : 100 harmful + 100 benign bare goals (intent control)
  * artifacts  : jailbreak prompt strings, grouped by attack family
      - JBC  : manual "jailbreak chat" templates (AIM / DAN-style)
      - PAIR : LLM-crafted adaptive social-engineering jailbreaks
      - GCG  : adversarial-suffix attacks (designed to evade filters)

  python -m calus.benchmark.external.jailbreakbench.build

The benign control for the artifact splits is the 100 benign JBB behaviors.
"""
import glob
import json
import os

from .._download import fetch_text

HERE = os.path.dirname(__file__)

HARMFUL_URL = ("https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors/"
               "resolve/main/data/harmful-behaviors.csv")
BENIGN_URL = ("https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors/"
              "resolve/main/data/benign-behaviors.csv")

ART_URL = ("https://raw.githubusercontent.com/JailbreakBench/artifacts/main/"
           "attack-artifacts/{method}/{sub}/{model}.json")

# Representative models per attack family (artifacts only exist for some pairs).
ARTIFACTS = {
    "JBC": ("manual", ["vicuna-13b-v1.5", "llama-2-7b-chat-hf",
                        "gpt-3.5-turbo-1106", "gpt-4-0125-preview"]),
    "PAIR": ("black_box", ["vicuna-13b-v1.5", "llama-2-7b-chat-hf",
                           "gpt-3.5-turbo-1106", "gpt-4-0125-preview"]),
    "GCG": ("transfer", ["gpt-3.5-turbo-1106", "gpt-4-0125-preview"]),
}


def _goals(url, cache):
    import csv
    import io

    raw = fetch_text(url, cache=cache)
    out, seen = [], set()
    for r in csv.DictReader(io.StringIO(raw)):
        line = " ".join((r.get("Goal") or "").split())
        if line and line not in seen:
            seen.add(line)
            out.append(line)
    return out


def _artifact_prompts(method, sub, models):
    out, seen = [], set()
    for model in models:
        cache = os.path.join(HERE, f"_art_{method}_{model}.json")
        try:
            raw = fetch_text(ART_URL.format(method=method, sub=sub, model=model),
                             cache=cache)
            data = json.loads(raw)
        except Exception:
            continue
        for j in data.get("jailbreaks", []):
            p = j.get("prompt")
            if p and p.strip():
                line = " ".join(str(p).split())
                if line not in seen:
                    seen.add(line)
                    out.append(line)
    return out


def main(argv=None):
    attacks = _goals(HARMFUL_URL, os.path.join(HERE, "_harmful.csv"))
    benign = _goals(BENIGN_URL, os.path.join(HERE, "_benign.csv"))
    with open(os.path.join(HERE, "attacks.txt"), "w", encoding="utf-8") as f:
        f.write("# JBB-Behaviors harmful behaviors — bare goals (NeurIPS 2024)\n")
        f.write("\n".join(attacks) + "\n")
    with open(os.path.join(HERE, "benign.txt"), "w", encoding="utf-8") as f:
        f.write("# JBB-Behaviors benign behaviors (topic-matched control)\n")
        f.write("\n".join(benign) + "\n")
    print(f"wrote {len(attacks)} harmful + {len(benign)} benign JBB behaviors")

    # Jailbreak artifacts (the real detection target), per attack family + combined.
    combined, seen = [], set()
    for method, (sub, models) in ARTIFACTS.items():
        prompts = _artifact_prompts(method, sub, models)
        path = os.path.join(HERE, f"artifacts_{method.lower()}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# JBB {method} jailbreak artifacts (real attack strings)\n")
            f.write("\n".join(prompts) + "\n")
        for p in prompts:
            if p not in seen:
                seen.add(p)
                combined.append(p)
        print(f"  {method:5s}: {len(prompts)} jailbreak prompts")
    with open(os.path.join(HERE, "artifacts_all.txt"), "w", encoding="utf-8") as f:
        f.write("# JBB jailbreak artifacts — all families combined\n")
        f.write("\n".join(combined) + "\n")
    print(f"  ALL  : {len(combined)} unique jailbreak prompts")
    print("now run:  python -m calus.benchmark.harness --dataset jailbreakbench")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
