# Calus — Debug / Test Report (intelligent cascade build)

## Final audit (all green)
| Check | Result |
|---|---|
| Compile all .py | **431 files, 0 errors** |
| Import every module | **0 core failures** (only optional `mcp`/`pytest`) |
| Brand-leakage (code/docs/config) | **0** — names survive only inside regex (detection targets) |
| Cross-OS (`fork` on scan path) | **none** — Windows/macOS/Linux safe |
| Smoke tests | **pass** |
| Functional cascade | attacks flag <30 ms, benign clean, base64 obfuscation decoded |
| Self-improving loop | **verified** — paraphrase of a `learn()`-ed attack is detected |
| Behavioral (agent context) | flags exfil tool calls + memory poisoning |

## Bugs found & fixed in this build
1. Decoders ran on every input (entropy gate too sensitive) → gated to real
   obfuscation signals only (base64 run / invisible unicode / spaced chars).
2. "Decisive clean" short-circuit skipped Tier 2 → paraphrases and learned
   signatures were never consulted. Fixed: only decisive *malicious* short-circuits;
   everything else reaches Tier 2.
3. Linux-only `fork` timeout removed from the scan path → now cross-OS via the
   calibrated set + caps + time budget.

## Earlier fixes retained
- Pure-Python Aho-Corasick fallback (no hard `pyahocorasick` dep).
- `guardrail_providers` plugin package + Calus MCP provider.
- 11,809 ReDoS + 16 nested-set + 134 uncompilable patterns quarantined.

## Not bugs (optional dependencies)
`mcp` SDK (`calus[mcp]`), `pytest` (`calus[dev]`), `pyahocorasick`/`re2`
(`calus[fast]`), `sentence-transformers`/`faiss` (`calus[semantic]`).
