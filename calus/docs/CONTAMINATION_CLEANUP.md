# Benchmark Contamination Cleanup (Layer 1)

Distinct integrity step, done **before** the gap-driven Layer-2 fixes, so that every
benchmark number reported afterward is honest.

## What was wrong

The Layer-1 rule packs and the prebuilt similarity indexes contained content
**derived from the very benchmarks we test against** — so any Layer-1 recall on
InjecAgent / AgentDojo was memorization, not generalization, and invalid as a
held-out measurement.

Evidence:
- `context_exfiltration` regexes templated on InjecAgent's data-stealing attacks,
  with the signature `amy.watson@gmail.com` (InjecAgent's attacker email) in the
  examples.
- 6 matching regexes (`prompt_injection_attacks` ×5, `acp_vulnerabilities` ×1)
  embedding AgentDojo's `important_instructions` template verbatim.
- Many more InjecAgent scenario strings across packs ("dell inspiron laptop",
  "my kitchen is on fire", "norton identity safe", "policy id", genetic/medical
  exfil phrasings) as examples/payloads.
- The prebuilt `attack_signatures.json` / `attack_index_v2.json` similarity indexes
  contained the same benchmark strings.

## What was removed

| Target | Action | Count |
|---|---|--:|
| Signature pass (`amy.watson`, AgentDojo template, by rule-id + marker) | removed lines from `patterns/**` | 75 |
| Convergent pass (≥40-char verbatim runs shared with the benchmark) | removed lines from `patterns/**` | 59 |
| `attack_signatures.json` benchmark-derived entries | text neutralized (structure preserved) | 21 + 37 |
| `attack_index_v2.json` benchmark-derived entries | text neutralized (structure preserved) | 21 + 37 |

Net engine rules: 27,864 → **27,802** active.

## Criterion (what is contamination vs what is legitimate)

- **Removed:** benchmark-**specific** content — proper nouns, scenario details,
  signature emails, and the AgentDojo template — anything sharing a **≥40-char
  verbatim run** with a benchmark row. A 40-char verbatim match is not coincidental;
  it indicates the rule was authored from the benchmark.
- **Kept:** generic attack idioms ("ignore all previous instructions", "ignore your
  previous instructions", "adhere to the following instruction"). These appear in
  the benchmarks because they are *real attack phrasings a detector should catch* —
  detecting them is generalization, not contamination.

## Verification

- Benchmark-specific (≥40-char verbatim) overlap with InjecAgent/AgentDojo: **0**.
- Residual ≥30-char overlap: **4**, all generic injection idioms (listed above).
- `amy.watson` / AgentDojo template in `patterns/` and indexes: **0**.
- Engine rebuilds cleanly; full test suite green.

## Consequence for the benchmark

- **Before cleanup:** Layer-1 InjecAgent/AgentDojo recall was contaminated → the
  valid signal was measured with **Layer 1 disabled (pure Layer 2)**.
- **After cleanup:** Layer 1 no longer contains benchmark-specific content, so
  full-engine (L1+L2) numbers are once again a fair generalization measure. Pure
  Layer 2 remains the architecture-validating, contamination-immune headline.

Backups of every edited source file were written alongside as `*.bak` during the
operation and removed after verification.
