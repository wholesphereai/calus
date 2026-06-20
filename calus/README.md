# Calus v3.0

**Always-on runtime threat detection for LangGraph — 24-layer detection engine, self-improving, zero commands needed.**

## Quick Start

```bash
pip install calus
```

```python
from calus import observe

secure = observe(graph, name="my_pipeline")
app = secure.compile()
result = app.invoke({"messages": [...]})
# Scanning is fully automatic. No other commands needed.
```

## 24-Layer Detection Architecture

```
Every message scanned through:

Layer 1 — Core (Deterministic, <2ms each)
  aho_corasick · encoding · entropy · heuristic · canary

Layer 2 — Extended (Deterministic)
  homoglyph · path_traversal · tool_alias · threat_categories

Layer 3 — Transform-Evasion (catches obfuscated attacks)
  ascii_smuggle  — Unicode TAG smuggling (U+E0000)
  morse          — Morse-encoded attacks
  binary         — Binary ASCII encoding
  braille        — Braille Unicode encoding
  charspace      — "i g n o r e" spaced-out text
  zalgo          — Combining diacritical mark abuse
  atbash         — Atbash cipher (a=z, b=y...)
  charswap       — Character swap evasion
  flip           — Reversed text attacks

Layer 4 — Behavioral
  memory_poison    — Agent memory poisoning attempts
  excessive_agency — Fake elevated permissions
  debug_access     — Debug/admin mode bypasses
  reasoning_dos    — Denial-of-service via computation
  cross_session    — Cross-session data leak attempts
  goal_misalign    — Subtle goal substitution

Layer 5 — Learned (Self-improving, auto-generated)
  Patterns mined from real attack corpus via TF-IDF + Jaccard clustering
```

## Pattern Library

**440+ attack patterns** in the bundled library:
- **Calus core** (234): new-instructions, DAN, poetry, sorry, policy-puppetry, test-mode, react-injection, data-exfil, XSS, sysmsg-extraction
- **Calus extended** (132): AIM, DAN variants, dev-mode, persona family, Pliny jailbreaks, Arth Singh authority exploits
- **Calus behavioral** (74): prompt-injection, indirect-injection, PII exfil, system prompt extraction, shell injection, SQL injection, RAG exfil

## Self-Improving Engine

Runs automatically in the background. No commands needed.

```
Every 10 threats detected:
  1. Deep normalizer (leet/unicode/base64/rot13/morse strips evasion)
  2. TF-IDF n-gram mining (threat corpus vs benign corpus)
  3. Jaccard similarity clustering
  4. Regex pattern generation
  5. Precision/specificity scoring (≥0.90 → auto-accept)
  6. Loaded into detection engine

Mutation engine generates 10 variants of every known attack:
  base64 · rot13 · leet · spaced · reversed · atbash
  random_caps · dot_joined · zero_width · unicode_sub
```

## CLI (5 commands)

```bash
calus                          # status panel
calus dashboard                # live rich terminal dashboard
calus add "attack phrase"      # add custom pattern (active immediately)
calus patterns                 # view pattern library
calus patterns --pending       # review pending learned patterns
calus patterns --accept 3      # accept pattern #3
calus patterns --accept-all    # accept all scoring ≥0.80
calus import attacks.jsonl     # import attack dataset
calus learn --run              # force learning cycle
calus learn --mutate           # generate obfuscated variants
```

## File Structure

```
calus/
├── detection/
│   ├── core/           # aho, encoding, entropy, heuristic, canary
│   ├── extended/       # homoglyph, path_traversal, tool_alias, threat_categories
│   ├── transforms/     # ascii_smuggle, morse, binary, braille, charspace,
│   │                   # zalgo, atbash, charswap, flip
│   ├── behavioral/     # memory_poison, excessive_agency, debug_access,
│   │                   # reasoning_dos, cross_session, goal_misalign
│   └── scanner.py      # orchestrates all 24 layers
├── learning/
│   ├── normalizer.py   # leet/unicode/base64/rot13/morse normalization
│   ├── miner.py        # TF-IDF n-gram mining
│   ├── evolver.py      # Jaccard clustering + regex generation
│   ├── engine.py       # orchestrator (auto-cycle every 10 threats)
│   ├── scheduler.py    # background daemon (daily at 02:00 UTC)
│   ├── mutator.py      # generates 10 obfuscated variants per attack
│   └── store.py        # SQLite persistence
├── patterns/
│   ├── Calus/         # 16 files, 234 patterns
│   ├── Calus/          # 6 files, 132 patterns
│   ├── Calus/      # 7 files, 74 patterns
│   └── community/      # drop your own .py files here
└── tui/
    ├── dashboard.py    # rich Live dashboard (multi-panel)
    └── theme.py        # color constants, layer groups
tests/
├── unit/               # normalizer, miner, evolver, scanner, store, scheduler
├── integration/        # full learning cycle, pattern loader, langgraph wrapper
└── patterns/           # Calus, Calus, Calus pattern validation
.github/workflows/
├── ci.yml              # test on Python 3.9-3.12 on every push
├── release.yml         # publish to PyPI on tag
└── security.yml        # weekly self-scan
```
