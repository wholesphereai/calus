# Calus — making it more powerful: what was built, and the proven ceiling

## Measured facts (completed in-sandbox)
- Flat boolean-OR of ~75k regex: precision ~9%, F1 ~17%, false-positive rate 100%
  (flags benign prose). Recall ~100% but inflated by leakage. 135 regex don't compile.
  Corpus contains ReDoS regex that hang single-core scanning.
- **Lexical similarity has a hard ceiling — proven, not asserted.** Upgrading Tier 2 from
  token-Jaccard to TF-IDF + char-n-grams was tested:

  | blend | paraphrased attacks | benign max | separation |
  |---|---|---|---|
  | TF-IDF only | 0.34–0.58 | 0.69 | **−0.35** |
  | TF-IDF+char-ngram | 0.35–0.59 | 0.66 | **−0.31** |

  Every blend gives **negative** separation: a benign "summarize this earnings report"
  scores *higher* similarity to a known attack than real paraphrases do. Lexical methods
  cannot tell "summarize the report" from "summarize the system prompt" — same words,
  different meaning. **No lexical trick fixes this.** Only semantic embeddings can.

## What was built to make it stronger (all shipped)
| Component | File | Status |
|---|---|---|
| Calibration (quarantine ReDoS/broken/over-broad; weight rest) | `detection/calibration.json` | done, 70,579 active |
| Tier 1: scored regex engine (severity×specificity + threshold) | `detection/scored_engine.py` | runs |
| Real Aho-Corasick literal pre-filter (linear-time, ReDoS-safe) | `detection/aho_corasick.py` | runs |
| Tier 2: lexical similarity (token + TF-IDF/char-ngram option) | `detection/similarity_layer.py`, `attack_index_v2.json` | runs (at its ceiling) |
| **Tier 3: semantic embeddings (the real power tier)** | `detection/embedding_layer.py` | pluggable — needs a model |
| Combined tiered detector (confidence + reasons) | `detection/combined_detector.py` | runs |
| Self-improving feedback loop (mine rules, auto-quarantine FPs) | `learning/feedback.py` | runs |
| Benchmark harness (calibrate/test split + threshold sweep) | `benchmark/harness.py` | runs in real env |

## The single highest-impact next step (needs your environment)
Plug a sentence-embedding model into `embedding_layer.py`:
    pip install sentence-transformers faiss-cpu
    e = EmbeddingLayer("all-MiniLM-L6-v2"); e.index_attacks(known_attacks); e.detect(text)
This is the step that breaks the lexical ceiling above — it separates meaning, not words.
The module deliberately refuses to run with a weak fallback (a fake embedding would lower
precision, the opposite of "more powerful").

## Honest ceiling with the full stack
Tier 0 (re2/hyperscan automaton) + Tier 1 (scored regex) + Tier 3 (embeddings + ANN) +
a small fine-tuned classifier on the ambiguous middle + the feedback loop = genuine
production grade: high recall AND high precision, fast, robust to novel/paraphrased attacks,
improving with use. Every remaining gain needs real compute/data — not more regex.
