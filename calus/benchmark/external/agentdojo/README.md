# AgentDojo detection benchmark (external, held-out)

[AgentDojo](https://github.com/ethz-spylab/agentdojo) (ETH Zurich, NeurIPS 2024 D&B)
is a benchmark for prompt-injection attacks against tool-using LLM agents: an
attacker hides an **injection goal** inside tool output, wrapped in an **attack
template** (`important_instructions`, `ignore_previous`, `injecagent`,
`system_message`, `tool_knowledge`). `benign.txt` is in-domain legitimate text
(emails, events, balances, messages) from the same workspace / banking / slack /
travel environments.

Calus is a **detector**, so this set answers: of AgentDojo's injected strings, how
many does Calus flag — and how often does it false-positive on legitimate text?

> HELD-OUT: this set is **not** in Calus's training data (`patterns/`,
> `attack_signatures.json`) and **not** in the unit tests. Use it only to measure
> generalization.

## Run it

```bash
# 1) generate the test set (bundled templates × injection goals, no extra deps)
python -m calus.benchmark.external.agentdojo.build

# 2) score the real engine
python -m calus.benchmark.harness --dataset agentdojo
```

For the **live** upstream suite instead of the bundled templates:

```bash
pip install agentdojo
python -m calus.benchmark.external.agentdojo.build --live
python -m calus.benchmark.harness --dataset agentdojo
```

## Files

| File          | What it is                                                    |
|---------------|--------------------------------------------------------------|
| `build.py`    | Generates `attacks.txt` / `benign.txt` (bundled or `--live`) |
| `attacks.txt` | AgentDojo injection strings, one per line                    |
| `benign.txt`  | Legitimate same-domain text (false-positive control)         |

## Reference numbers (bundled set, `calus.scan`, 108 injections + 20 benign)

```
recall ≈ 73%   precision ≈ 97%   F1 ≈ 84%        (engine default verdict)
recall ≈ 95%   precision ≈ 92%   F1 ≈ 94%        (confidence ≥ 0.20)
```

A smoke benchmark on representative templates, not a leaderboard score. For a
defensible number, run `--live` against the current AgentDojo suite and report the
engine + threshold used. Detection-only: Calus flags these injections for
observability; it does not block the agent.

Source: https://github.com/ethz-spylab/agentdojo (MIT License). Attribution kept
per the dataset's origin; payloads are used for detection benchmarking.
