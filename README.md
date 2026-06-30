<div align="center">

<img src="assets/logo.png" alt="Calus" width="104" />

# Calus

**A drop-in security gateway for AI agents. No code changes. No SDK.**

Calus sits between your AI tools and the model providers. Every call is verified
through two deterministic layers and a single decision engine that **blocks
confirmed agent attacks and flags the uncertain ones** — with full OWASP LLM
Top 10 observability on every request.

</div>

---

## How it works — two layers, one decision

Every input passes a **two-step verification**, then a single **decision engine**
decides. The layers only *observe* and emit a signal; the decision engine is the
**only** component that can block.

```
                ┌──────────────┐     ┌──────────────────┐     ┌─────────────────┐
   input ─────▶ │   Layer 1    │ ──▶ │     Layer 2      │ ──▶ │ Decision engine │ ──▶ block / flag / pass
                │  patterns    │     │ capability-flow  │     │  (the referee)  │
                └──────────────┘     └──────────────────┘     └─────────────────┘
                 injection /          untrusted origin →        combines both
                 jailbreak text       RED capability sink        signals + risk
```

| Step | What it does |
|---|---|
| **Layer 1 — pattern fast-path** | Deterministic regex + obfuscation decoders + lexical similarity over known injection / jailbreak signatures. Emits a signal (block / pass + confidence). |
| **Layer 2 — capability-flow graph** | Taint tracking: each input carries an origin (trusted vs untrusted) and each tool resolves to a capability sink (RED / LOW). An untrusted origin reaching a RED sink is a forbidden edge. Emits a signal. |
| **Decision engine** | The referee. It combines both signals with the **consequence** (is an irreversible/external action pending?) and applies one fixed, audited rule table. |

**The verdict is consequence-aware:**

- **BLOCK** — a confirmed threat (high-confidence pattern hit, or a forbidden
  capability-flow edge) on a **high-consequence** action (something irreversible
  or external — sending, paying, executing, unlocking).
- **FLAG** — uncertain, or a real threat with no high-consequence action pending.
  Allowed, but logged with full detail.
- **PASS** — both layers clean.

Only the decision engine blocks. It is deterministic (same input → same verdict),
fully auditable (every verdict records which rule fired and each layer's signal),
and fail-safe (if a layer errors on a high-consequence action, it fails toward a
block). A request is **never** blocked until it has been confirmed by the decision
engine.

---

## Benchmark

Scored by the real engine (Layer 1 + Layer 2 + decision engine) on held-out,
third-party benchmarks, post-contamination-cleanup, with no tuning to the test.
**caught** = detected (block + flag); **blocked** = the enforced stop in gateway
mode; **missed** = passed undetected.

| Benchmark | Type | N | caught | blocked | missed |
|---|---|--:|:--:|:--:|:--:|
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) — indirect prompt injection | agent action | 2,108 | **100%** | **80.6%** | 0 |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) — injection strings | text-only | 162 | 82.7% | 0% | 28 |

Benign false-positive rate: **3.5%** (72 / 2,037 — Databricks Dolly-15k +
AgentDojo-benign + InjecAgent benign flows). Precision on the agent-injection
set: **96.9%**.

**What the numbers mean.** On InjecAgent every data-stealing or harmful chain ends
in a RED action, so Layer 2's capability-flow graph catches the attack *by
consequence* even when no text pattern fires — that is what drives **100% caught
/ 80.6% blocked / 0 missed**. The remaining ~19% are *flagged* (detected, not
blocked) because the attacker tool did not map to a RED sink. AgentDojo is
text-only locally (no agent action), so Layer 2 has nothing to act on — its 82.7%
is Layer 1 catching the injection wording, nothing blocked.

**Disclosed scope boundary.** Calus is an injection / agent-flow detector, not a
harmful-content classifier or an adaptive-attack solver. On direct-prompt jailbreak
and harmful-content corpora it is deliberately weak (JailbreakBench 6.0%, AdvBench
2.5%, HarmBench 6.8% caught) — pair it with a content-moderation classifier for
that layer. Adaptive / novel injections remain a known gap.

```bash
# Build a held-out test set, then score the real engine:
python -m calus.benchmark.external.injecagent.build
python -m calus.benchmark.harness --dataset injecagent   # also: agentdojo, jailbreakbench, advbench, harmbench
```

Methodology and per-split detail:
[`calus/docs/LAYER_BENCHMARK_REPORT.md`](calus/docs/LAYER_BENCHMARK_REPORT.md) ·
[contamination cleanup](calus/docs/CONTAMINATION_CLEANUP.md).

---

## What you get

- **Drop-in proxy.** Point any OpenAI-compatible app at Calus with one environment
  variable. No code changes, no SDK.
- **Detect or block.** Run detection-only (verdict mode, default) or turn on
  gateway-block to stop confirmed attacks at the proxy.
- **Multi-provider.** OpenAI, Groq, Anthropic, Gemini, Mistral, Cohere, and
  anything [LiteLLM](https://github.com/BerriAI/litellm) supports, by `model` prefix.
- **Agent & tool observability.** Every agent, its tools, and the calls it makes
  (arguments redacted) are traced, mapped to the OWASP LLM Top 10 (2025).
- **Secret & PII redaction** before anything is stored, and an **encrypted key
  vault** so provider keys are never written to the call log.
- **Console.** Overview, Agents, Threats, Live calls, API keys, Connect.

---

## Quick start (Docker)

```bash
git clone https://github.com/wholesphereai/calus.git
cd calus
docker compose up --build
```

- Dashboard: http://localhost:5173
- Proxy: http://localhost:8000

The proxy auto-generates an admin token at startup and the dashboard picks it up —
no login prompt on localhost. Add your provider keys from the **API Keys** tab.

## Quick start (local, no Docker)

```bash
git clone https://github.com/wholesphereai/calus.git
cd calus
python -m venv .venv && . .venv/Scripts/activate     # Windows
# source .venv/bin/activate                          # macOS / Linux

python -m pip install -e calus                       # 1) engine

cd proxy                                             # 2) proxy (terminal 1)
python -m pip install -r requirements.txt
python -m uvicorn calus_proxy.main:app --port 8000

cd dashboard                                         # 3) dashboard (terminal 2)
npm install && npm run dev                           # http://localhost:5173
```

---

## Point your app at Calus

One environment variable. Calus forwards every call with your own provider key —
used in-flight, never written to any log or store.

```bash
export OPENAI_BASE_URL="http://localhost:8000/v1"
# that's it — run your app as usual
```

**Name your agents** so their traffic shows up separately in the dashboard
(otherwise everything lands under "unknown"). Two equivalent ways — pick whichever
your SDK exposes:

| Method | How | Best for |
|---|---|---|
| `user` field | Standard OpenAI body field | OpenAI SDK, any JSON client |
| `X-Calus-Agent` header | HTTP header, not part of the LLM payload | LangChain, frameworks without `user` |

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8000/v1", api_key="sk-your-own-key")

client.chat.completions.create(
    model="groq/llama-3.3-70b-versatile",
    user="my-agent",                         # shows up as "my-agent" in the dashboard
    messages=[{"role": "user", "content": "Hello"}],
)
```

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer sk-your-own-key" \
  -H "X-Calus-Agent: my-agent" \
  -H "Content-Type: application/json" \
  -d '{"model":"groq/llama-3.3-70b-versatile","messages":[{"role":"user","content":"Hello"}]}'
```

The **Connect** tab in the dashboard has ready-to-paste snippets for every SDK
(Node, LangChain, Claude Code, …).

### Read the verdict from response headers

Every response carries the decision inline, so a SIEM can act on it without the
dashboard:

| Header | Values | Meaning |
|---|---|---|
| `x-calus-action` | `block` / `flag` / `pass` | The decision engine's verdict |
| `x-calus-consequence` | `high` / `low` | Whether a high-consequence action was in play |
| `x-calus-confidence` | `0.00` – `1.00` | Detection confidence |
| `x-calus-owasp` | e.g. `LLM01` | OWASP LLM Top 10 category, if flagged |
| `x-calus-enforced` | `true` / `false` | Whether the request was actually stopped (gateway mode) |

---

## Detection vs blocking

Calus ships in **verdict mode** (detection-only) so it stays a safe drop-in. Flip
one variable to turn on enforcement.

| `CALUS_ENFORCE_MODE` | Behaviour |
|---|---|
| `verdict` (default) | Observe and flag. The decision is surfaced in `x-calus-*` headers and the dashboard; the request is never stopped. |
| `gateway` | Enforce. A **BLOCK** decision returns `403` on the input, or replaces a forbidden tool-call response. Only confirmed (decision-engine) blocks stop a request. |

```bash
export CALUS_ENFORCE_MODE=gateway     # turn on blocking
```

---

## Provider keys

Let callers send their own key per request (BYOK, nothing stored), or save keys in
the encrypted vault. Saved keys are encrypted at rest, shown masked, and used to
forward upstream when a request carries no key of its own.

1. **Dashboard** — API Keys tab: pick a provider, paste, Add.
2. **CLI** — `python -m calus_proxy.keys add --provider groq --key gsk_... --label prod`
3. **Environment** — put `OPENAI_API_KEY`, `GROQ_API_KEY`, … in `proxy/.env`.

Resolution order: caller's bearer key → saved vault key → env key.

## Configuration (`proxy/.env`)

| Variable | Default | Meaning |
|---|---|---|
| `CALUS_ENFORCE_MODE` | `verdict` | `verdict` (flag only) or `gateway` (block confirmed attacks). |
| `CALUS_ADMIN_TOKEN` | auto-generated | Token the dashboard/API present. Blank → auto-generate at startup. |
| `CALUS_PROXY_TOKEN` | blank | Optional data-plane token. If set, `/v1/*` requires it. |
| `CALUS_FLAG_THRESHOLD` | `0.5` | Confidence at/above which a call is recorded as flagged. |
| `CALUS_SCAN_RESPONSES` | `1` | Also verify model responses (and their tool calls). |
| `CALUS_REDACT_STORE` | `1` | Redact secrets and PII before storing. |
| `CALUS_DB_PATH` | `calus_proxy.db` | SQLite log store path. |
| `CALUS_SECRET` | admin token | Master secret for the encrypted key vault. |

---

## Security

- **Verdict mode passes traffic through untouched;** only `gateway` mode stops a
  request, and only on a confirmed decision-engine block.
- **Provider keys are never written to the log store.** Saved keys live in an
  encrypted vault, decrypted only in memory to forward a request.
- **Secrets and PII are redacted** before any text or tool-call arguments are stored.
- **Securing the data plane.** `/v1/*` is unauthenticated by default so Calus stays
  drop-in — fine on localhost or a private network. If you expose the port, set
  `CALUS_PROXY_TOKEN` (constant-time checked) so it can't become an open relay.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[MIT](LICENSE). Use it freely, including in commercial and closed-source products.
Just keep the copyright and license notice.
