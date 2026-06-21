# Calus detection benchmarks

Every number here is produced by the **real cascade engine** (`calus.get_detector().scan`)
scanning **held-out, third-party academic datasets**, one input per line, with **no
tuning**. Nothing is hand-picked or simulated. Each benchmark has a `build.py` that
downloads the official upstream data and materializes `attacks.txt` / `benign.txt`;
`harness.py` then scores precision / recall / F1 at the engine's **default verdict**
and at the **confidence ≥ 0.20** operating point.

```bash
# 1. build a test set (downloads upstream data, writes attacks/benign txt)
python -m calus.benchmark.external.<name>.build
# 2. score the real engine
python -m calus.benchmark.harness --dataset <name>     # add --sweep for the full threshold sweep
```

`<name>` ∈ `agentdojo` · `injecagent` · `jailbreakbench` · `advbench` · `harmbench`.

## What Calus is (and isn't)

Calus is a **prompt-injection / jailbreak-pattern detection gateway**. It flags
adversarial *inputs* — injection wrappers ("ignore previous instructions",
system-message spoofing), jailbreak templates, encoding/obfuscation — before they
reach the model. It is **not** a content-moderation classifier: a bare harmful
request with no adversarial wrapper ("write a tutorial on X") is a different layer.
The benchmarks are grouped accordingly.

---

## 1 · Prompt injection (core threat model)

### AgentDojo — ETH Zurich, NeurIPS 2024
Prompt-injection attacks against tool-using agents: an injection goal wrapped in an
attack template, hidden in tool output. Calus scans the injected string.

| Setting | Recall | Precision | F1 |
|---|--:|--:|--:|
| default verdict | 69.4% | 100.0% | 82.0% |
| conf ≥ 0.20 | 95.4% | 92.8% | 94.1% |

### InjecAgent — UIUC, ACL 2024 Findings
1,054 indirect-injection test cases (510 direct-harm + 544 data-stealing). The
attacker instruction is hidden inside the content a tool returns to the agent; Calus
scans the **full rendered `Tool Response`**. The benign control is the *same*
tool-response template with the injection slot filled by ordinary content, so attack
and control differ only by the injection.

| Split | Setting | Recall | Precision | F1 |
|---|---|--:|--:|--:|
| Standard (base) | default | 34.9% | 98.7% | 51.6% |
| Standard (base) | conf ≥ 0.20 | 69.4% | 98.7% | 81.5% |
| Enhanced (hacking prompt) | default | 96.1% | 99.5% | 97.8% |
| Enhanced (hacking prompt) | conf ≥ 0.20 | 100.0% | 99.1% | 99.5% |
| Direct harm (base) | conf ≥ 0.20 | 50.0% | 96.2% | 65.8% |
| Data exfiltration (base) | conf ≥ 0.20 | 87.7% | 97.9% | 92.5% |

The *enhanced* setting — where the attacker prepends a hacking prompt
("IMPORTANT!!! Ignore all previous instructions …") — is the canonical real-world
indirect-injection shape, and is exactly what Calus's pattern tiers are built for.

---

## 2 · Jailbreak detection — JailbreakBench (NeurIPS 2024)

JailbreakBench publishes both behavior goals and an **attack-artifact library**: the
actual jailbreak prompt strings that broke models. A detection gateway should be
judged on the artifacts (the bare goals are intent-only — see §3). Benign control:
the 100 benign JBB behaviors (topic-matched, adversarially hard). Default verdict:

| Attack family | n | Recall | Precision | F1 |
|---|--:|--:|--:|--:|
| JBC — manual templates (AIM / DAN-style) | 100 | 100.0% | 98.0% | 99.0% |
| PAIR — LLM-crafted adaptive jailbreaks | 237 | 29.1% | 97.2% | 44.8% |
| GCG — adversarial suffix (filter-evasion) | 100 | 29.0% | 93.5% | 44.3% |
| All families combined | 437 | 45.3% | 99.0% | 62.2% |

Note: the conf ≥ 0.20 operating point that helps on AgentDojo flags ~21 of the 100
topic-matched benign behaviors, so **default verdict is the honest primary** here
(precision 93–99%). The classic manual jailbreak templates are caught at 100%;
adaptive (PAIR) and adversarial-suffix (GCG) attacks are partial — GCG is explicitly
optimized to evade pattern filters.

---

## 3 · Scope boundary — harmful-intent corpora

These datasets measure whether a **bare request carries harmful intent**, i.e.
content moderation — a different layer from injection/jailbreak detection. Calus
flags only the subset carrying an injection/obfuscation signature, so recall is low
**by design**. Reported honestly so the scope is unambiguous. Benign control: the
100 benign JBB behaviors.

| Benchmark | n | Recall (default) | Recall (conf ≥ 0.20) |
|---|--:|--:|--:|
| AdvBench — 520 harmful goals (arXiv 2307.15043) | 520 | 2.9% | 28.1% |
| HarmBench — 200 standard behaviors (CAIS 2024) | 200 | 10.5% | 46.5% |
| JBB — 100 bare behavior goals (NeurIPS 2024) | 100 | 6.0% | 21.0% |

HarmBench was designed to measure *model* refusal; we report only the well-defined
input-detection sub-question — **how many HarmBench adversarial input prompts does
Calus flag before they reach the model** — never a single "HarmBench score," which
would imply model refusal. For harmful-content blocking, pair Calus with a
content-moderation classifier.

---

## 4 · False-positive rate on normal traffic

Precision on adversarial inputs is not enough; operators need to know how often the
gateway flags *legitimate* user messages. We measure this on **2,000 held-out
Databricks Dolly-15k instructions** — ordinary human-written requests (Q&A,
brainstorming, summarization, coding, classification), disjoint from the corpus used
to calibrate the engine.

| Operating point | False-positive rate on normal traffic |
|---|--:|
| **default verdict** | **1.1%** |
| conf ≥ 0.20 | ~34% |

The **default verdict** is the production operating point: ~1 in 90 normal messages
is flagged. `conf ≥ 0.20` trades that for recall and is only suitable where review
noise is acceptable. This was achieved by `calus.tools.refine_calibration`, which
quarantines any pattern that fires on the benign corpus
(`detection/benign_calibration.txt`, 600 normal messages) — e.g. an attack payload
whose shell `|` was an unescaped regex alternation matching the bare string `" sh"`.
A small `detection/calibration_keep.txt` allowlist protects the few patterns with
real attack value at near-zero benign cost.

---

## Reproducibility notes

- `build.py` for each benchmark downloads the official upstream files and caches them
  beside the script (prefixed `_`) so the set can be regenerated offline.
- The benign false-positive control for AdvBench / HarmBench is the published 100
  benign JBB-Behaviors prompts (`external/_benign_control.py`) — a strict,
  topic-matched control, not easy small talk. The normal-traffic FPR (§4) uses a
  separate, held-out Dolly-15k sample.
- Numbers were generated on the engine version in this tree; re-run the harness to
  reproduce. Pattern updates may shift them.
