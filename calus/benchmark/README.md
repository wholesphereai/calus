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
| default verdict | 73% | 97% | 84% |
| conf ≥ 0.20 | 95% | 92% | 94% |

### InjecAgent — UIUC, ACL 2024 Findings
1,054 indirect-injection test cases (510 direct-harm + 544 data-stealing). The
attacker instruction is hidden inside the content a tool returns to the agent; Calus
scans the **full rendered `Tool Response`**. The benign control is the *same*
tool-response template with the injection slot filled by ordinary content, so attack
and control differ only by the injection.

| Split | Setting | Recall | Precision | F1 |
|---|---|--:|--:|--:|
| Standard (base) | default | 41.2% | 95.4% | 57.5% |
| Standard (base) | conf ≥ 0.20 | 72.4% | 97.0% | 82.9% |
| Enhanced (hacking prompt) | default | 96.5% | 98.0% | 97.2% |
| Enhanced (hacking prompt) | conf ≥ 0.20 | 100.0% | 97.8% | 98.9% |
| Direct harm (base) | conf ≥ 0.20 | 56.1% | 92.3% | 69.8% |
| Data exfiltration (base) | conf ≥ 0.20 | 87.7% | 95.2% | 91.3% |

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
| JBC — manual templates (AIM / DAN-style) | 100 | 100.0% | 94.3% | 97.1% |
| PAIR — LLM-crafted adaptive jailbreaks | 237 | 49.8% | 95.2% | 65.4% |
| GCG — adversarial suffix (filter-evasion) | 100 | 34.0% | 85.0% | 48.6% |
| All families combined | 437 | 57.7% | 97.7% | 72.5% |

Note: the conf ≥ 0.20 operating point that helps on AgentDojo flags ~25 of the 100
topic-matched benign behaviors, so **default verdict is the honest primary** here
(precision 94–98%). The classic manual jailbreak templates are caught at 100%;
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
| AdvBench — 520 harmful goals (arXiv 2307.15043) | 520 | 4.8% | 30.8% |
| HarmBench — 200 standard behaviors (CAIS 2024) | 200 | 16.5% | 49.5% |
| JBB — 100 bare behavior goals (NeurIPS 2024) | 100 | 12.0% | 26.0% |

HarmBench was designed to measure *model* refusal; we report only the well-defined
input-detection sub-question ("does Calus flag the input before it reaches the
model?"), never a single "HarmBench score," which would imply model refusal. For
harmful-content blocking, pair Calus with a content-moderation classifier.

---

## Reproducibility notes

- `build.py` for each benchmark downloads the official upstream files and caches them
  beside the script (prefixed `_`) so the set can be regenerated offline.
- The benign false-positive control for AdvBench / HarmBench is the published 100
  benign JBB-Behaviors prompts (`external/_benign_control.py`) — a strict,
  topic-matched control, not easy small talk.
- Numbers were generated on the engine version in this tree; re-run the harness to
  reproduce. Pattern updates may shift them.
