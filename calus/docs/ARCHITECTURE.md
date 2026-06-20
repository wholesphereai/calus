# Calus — Intelligent Cascade Architecture

Designed to match the consensus of production tools (Rebuff, Vigil, LLM Guard)
and the OWASP LLM Prompt-Injection cheat sheet: a **confidence-routed cascade**
(cheap → expensive). Every layer is kept, but the engine decides per-input how
deep to go, so average latency stays at Tier-1 speed.

```
            ┌─────────────────────────────────────────────┐
 input ───▶ │ Tier 1  Deterministic (calibrated regex)     │
            │   + cheap anomaly signals (entropy, unicode)  │
            │   + decoders (base64/spaced/reversed) ON ANOMALY ONLY │
            └───────────────┬─────────────────────────────┘
              score ≥ 6.0 ──┴─▶ FLAG (stop; skip deeper tiers)
              otherwise ──────▶┐
            ┌──────────────────▼──────────────────────────┐
            │ Tier 2  Lexical / vector similarity           │  (cheap, always
            │   to the known-attack corpus                  │   reached if not
            └───────────────┬─────────────────────────────┘   decisively malicious)
              sim ≥ 0.55 ───┴─▶ FLAG
              otherwise ──────▶┐
            ┌──────────────────▼──────────────────────────┐
            │ Tier 3  Semantic classifier / embeddings      │  (pluggable;
            │   (Prompt-Guard / sentence-transformers)      │   runs only here)
            └───────────────┬─────────────────────────────┘
                            │
            ┌───────────────▼─────────────────────────────┐
            │ Behavioral / action screening (agent context) │  (parallel: tool
            │   excessive agency, exfil tools, memory poison │   calls, memory)
            └─────────────────────────────────────────────┘
```

## When each layer runs ("use what, when")
| Layer | Runs when | Cost |
|---|---|---|
| Tier 1 regex | always | ~5–30 ms |
| Decoders | only on obfuscation signal (base64 run, invisible unicode, spaced chars) | tiny |
| Tier 2 similarity | only if Tier 1 is not decisively malicious | ~ms |
| Tier 3 semantic | only if plugged in AND Tiers 1–2 uncertain | model-dependent |
| Behavioral | only when `agent_context` is supplied | tiny |

## Self-improving loop
```python
import calus
r = calus.scan(text)
# human/CI confirms the verdict:
calus.learn(text, is_attack=True)          # hardens Tier 2 immediately + queues a rule
calus.learn(benign_text, is_attack=False, matched_rule_ids=[...])  # queues quarantine
```
Confirmed attacks are added to the live similarity index (recall improves at once)
and a candidate regex is mined for review; confirmed false positives queue the
offending rules for quarantine (precision improves). Verified end-to-end: after
`learn()` on a novel attack, a paraphrase of it is detected via Tier 2.

## Safety / portability
- **Cross-OS, zero hard dependencies** (Windows/macOS/Linux). No `fork`, no native libs.
- Regex tier uses the calibrated set (ReDoS/over-broad patterns removed) + input cap
  + candidate cap + wall-clock budget, so a scan cannot hang on any platform.
- Optional speed/accuracy backends: `calus[fast]` (re2/pyahocorasick), `calus[semantic]`
  (sentence-transformers + faiss), `calus[mcp]`.

## Tuning
Thresholds `T1_DECISIVE`, `T2_FLAG` in `detection/cascade_engine.py` are the
precision/recall knobs. Tune them on a real benchmark (`calus.benchmark.harness`)
with held-out attacks + genuinely benign text. Do not trust default numbers.
