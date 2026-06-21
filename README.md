<div align="center">

# Calus

**A drop-in AI-security gateway. No code changes. No SDK.**

Calus sits between your AI tools and the model providers — giving you instant
**threat detection**, **agent & tool-call observability**, and **OWASP LLM Top 10**
coverage on every call. Detection-only: it observes and flags, it never blocks or
alters your traffic.

_by **Wholesphere**_

</div>

---

## 🛡️ Benchmark Coverage

Calus ships with **27,871 detection patterns** across **41 rule packs**, mapped to
the **OWASP LLM Top 10 (2025)**. It is a **prompt-injection / jailbreak-pattern
detection gateway** — it flags adversarial *inputs* (injection wrappers, jailbreak
templates, obfuscation) before they reach the model. Every number below is scored
by the **real engine** against **held-out, third-party academic benchmarks**, with
**zero tuning**. Reproduce any row with the commands in
[`calus/benchmark`](calus/benchmark).

### 1 · Prompt injection — Calus's core threat model

| Benchmark | Setting | Recall | Precision | F1 |
|---|---|:--:|:--:|:--:|
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) · NeurIPS 2024 | default | 73% | 97% | 84% |
| | conf ≥ 0.20 | **95%** | 92% | **94%** |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) · ACL 2024 — Standard | default | 41% | 95% | 58% |
| | conf ≥ 0.20 | 72% | 97% | 83% |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) · ACL 2024 — Enhanced | default | 97% | 98% | 97% |
| | conf ≥ 0.20 | **100%** | 98% | **99%** |

InjecAgent's *enhanced* setting (attacker prepends a "hacking prompt") is the
common real-world indirect-injection shape — Calus catches **100%** of its 1,054
injected tool responses at conf ≥ 0.20, at 98% precision. By attack type
(conf ≥ 0.20): data-exfiltration **F1 91%**, direct-harm **F1 70%**.

### 2 · Jailbreak detection — JailbreakBench artifacts (NeurIPS 2024)

Scored against the **real jailbreak attack strings** in JailbreakBench's artifact
library (the meaningful detection target), with the 100 benign JBB behaviors as
the false-positive control. Default verdict shown (precision-led):

| Attack family | Recall | Precision | F1 |
|---|:--:|:--:|:--:|
| JBC — manual templates (AIM / DAN-style) | **100%** | 94% | 97% |
| PAIR — LLM-crafted adaptive jailbreaks | 50% | 95% | 65% |
| GCG — adversarial suffix (filter-evasion) | 34% | 85% | 49% |
| **All families combined** | 58% | 98% | 73% |

Calus catches **every** classic manual jailbreak template, the majority of
adaptive social-engineering jailbreaks, and a third of gibberish suffix attacks
explicitly designed to slip past filters.

### 3 · Scope boundary — harmful-intent corpora

[AdvBench](https://github.com/llm-attacks/llm-attacks) (520 prompts) and
[HarmBench](https://github.com/centerforaisafety/HarmBench) (200 standard
behaviors) measure whether a **bare request carries harmful intent**
("write a tutorial on …") — that is *content moderation*, a different layer from
injection/jailbreak detection. Calus is not a content classifier; it flags only
the subset of these prompts that carry an injection or obfuscation signature, so
recall is low **by design**:

| Benchmark | Recall (default) | Recall (conf ≥ 0.20) |
|---|:--:|:--:|
| AdvBench — 520 harmful goals | 5% | 31% |
| HarmBench — 200 standard behaviors | 17% | 50% |

For harmful-content blocking, pair Calus with a content-moderation classifier;
Calus owns the injection/jailbreak layer those classifiers miss.

```bash
# Build any test set, then score the real engine (one input per line):
python -m calus.benchmark.external.injecagent.build
python -m calus.benchmark.harness --dataset injecagent      # also: agentdojo,
                                                            # jailbreakbench, advbench, harmbench
```

Methodology, sources and per-split numbers →
[`calus/benchmark/README.md`](calus/benchmark/README.md).

---

## What you get

- **Drop-in proxy** — point any OpenAI-compatible app at Calus by setting one
  environment variable. No code changes, no SDK to install.
- **Multi-provider** — OpenAI, Groq, Anthropic, Gemini, Mistral, Cohere… anything
  [LiteLLM](https://github.com/BerriAI/litellm) supports, selected by the `model` prefix.
- **Threat detection** — a tiered engine (regex → lexical similarity → optional
  semantic) flags prompt injection, jailbreaks, agent abuse and more, mapped to the
  **OWASP LLM Top 10 (2025)**.
- **Agent & tool observability** — every agent, the tools it can call, and the tool
  calls it actually makes (arguments redacted) are traced in the console.
- **Secret/PII redaction** — secrets and PII are masked before anything is stored.
- **Encrypted key vault** — optionally save provider keys; stored encrypted at rest,
  shown masked, revealed on demand. Provider keys are **never** written to the call log.
- **Monochrome console** — a clean black-and-white dashboard: Overview, Agents,
  Threats, Live calls, API keys, and Connect.

## Architecture

```
your app ──(your key)──▶  CALUS PROXY  ──(same key)──▶  OpenAI / Groq / Anthropic / …
                              │
                       scan + log verdict
                     (key used in-flight, never stored)
                              │
                              ▼
                      CALUS DASHBOARD  (you watch live)
```

| Component   | Path                | What it is                                            |
|-------------|---------------------|-------------------------------------------------------|
| Engine      | `calus/`            | Pure-Python detection library (`pip install -e calus`)|
| Proxy       | `proxy/calus_proxy` | FastAPI OpenAI-compatible gateway + dashboard API     |
| Dashboard   | `dashboard/`        | React + TypeScript (Vite) console                     |

```
calus/
├── README.md  LICENSE  SECURITY.md  CONTRIBUTING.md
├── Dockerfile  docker-compose.yml  .dockerignore
├── .github/workflows/        # ci · security · release
│
├── calus/                    # detection engine (Python package)
│   ├── pyproject.toml  api.py  cli.py  owasp.py
│   ├── detection/            # cascade engine, scored regex, similarity, redaction
│   ├── patterns/             # 27k+ OWASP-mapped rule packs
│   ├── learning/  context/  integrations/  tools/
│   ├── benchmark/            # accuracy harness + AgentDojo set
│   ├── tests/
│   └── docs/                 # architecture, threat coverage, accuracy
│
├── proxy/                    # the gateway
│   ├── requirements.txt  .env.example
│   └── calus_proxy/
│       ├── main.py           # OpenAI-compatible routes + dashboard API
│       ├── config.py  store.py  crypto.py  keys.py
│
└── dashboard/                # React + TS console
    ├── package.json  index.html  vite.config.ts  Dockerfile  nginx.conf
    └── src/  ( App · components · api · types · index.css )
```

---

> **Setup is fast.** Installing dependencies takes ~1–2 min the first time; after
> that the proxy boots and warms its 27k-pattern engine in **~5 seconds**, then
> scans in ~15 ms. No model downloads, no GPU.

## Quick start — Docker (recommended)

```bash
git clone https://github.com/wholesphereai/calus.git
cd calus
cp proxy/.env.example proxy/.env     # add your provider keys (admin token optional)
docker compose up --build
```

- Dashboard → http://localhost:5173
- Proxy     → http://localhost:8000

**Admin token:** you don't have to set one. If `CALUS_ADMIN_TOKEN` is left blank,
the proxy **auto-generates** a token and **prints it in the startup logs** — copy
that into the dashboard. Set your own in `proxy/.env` only if you want it stable
across restarts.

## Quick start — local (no Docker)

```bash
git clone https://github.com/wholesphereai/calus.git
cd calus
python -m venv .venv && . .venv/Scripts/activate     # Windows
# source .venv/bin/activate                          # macOS/Linux

# 1) engine
python -m pip install -e calus

# 2) proxy  (terminal 1)
cd proxy
python -m pip install -r requirements.txt
cp .env.example .env          # add provider keys; admin token auto-generates if blank
python -m uvicorn calus_proxy.main:app --port 8000   # prints the admin token on first run

# 3) dashboard  (terminal 2)
cd dashboard
npm install
npm run dev                   # http://localhost:5173
```

---

## Point your app at Calus (the "no code changes" part)

Set one environment variable and run your app as usual — Calus forwards each call
with **your own provider key** (used in-flight, never stored):

```bash
export OPENAI_BASE_URL="http://localhost:8000/v1"
```

…or pass the base URL explicitly:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",   # ← route through Calus
    api_key="sk-your-own-key",
)
client.chat.completions.create(
    model="groq/llama-3.3-70b-versatile",   # any provider via prefix
    user="my-agent",                        # names this agent in the console
    messages=[{"role": "user", "content": "hello"}],
)
```

Name each agent with the OpenAI `user` field (or an `X-Calus-Agent` header) so its
traffic and tool calls show up separately. The **Connect** tab in the dashboard has
copy-paste snippets for the OpenAI SDK, Claude Code, LangChain, and curl.

---

## Add provider keys — three ways

You can let callers send their own key per request (BYOK, nothing stored), or save
keys in Calus's **encrypted vault** so you don't re-paste them. Saved keys are
encrypted at rest, shown masked, and used to forward upstream when a request
doesn't carry its own.

1. **Dashboard** → the **API keys** page: pick a provider, paste the key, Add.
   Reveal / delete any time.
2. **Command line** (same vault):
   ```bash
   cd proxy
   python -m calus_proxy.keys add --provider groq --key gsk_... --label prod
   python -m calus_proxy.keys list
   python -m calus_proxy.keys delete <id>
   ```
3. **Environment** → put `OPENAI_API_KEY`, `GROQ_API_KEY`, … in `proxy/.env`
   (read by LiteLLM, never stored in the log).

Resolution order when forwarding: caller's bearer key → saved vault key → env key.

---

## Configuration (`proxy/.env`)

| Variable               | Default              | Meaning                                            |
|------------------------|----------------------|----------------------------------------------------|
| `CALUS_ADMIN_TOKEN`    | _(auto-generated & printed)_ | Token the dashboard/API must present. Leave blank to auto-generate one at startup |
| `CALUS_CORS_ORIGINS`   | `http://localhost:5173` | Allowed dashboard origins                       |
| `CALUS_DB_PATH`        | `calus_proxy.db`     | SQLite log store path                              |
| `CALUS_REDACT_STORE`   | `1`                  | Redact secrets/PII before storing                  |
| `CALUS_STORE_TEXT`     | `1`                  | Store redacted prompt/response preview             |
| `CALUS_SCAN_RESPONSES` | `1`                  | Also scan model responses                          |
| `CALUS_FLAG_THRESHOLD` | `0.5`                | Confidence at/above which a call is flagged         |
| `CALUS_SECRET`         | _(admin token)_      | Master secret for the encrypted key vault          |
| `OPENAI_API_KEY`, `GROQ_API_KEY`, … | —       | Upstream keys (read by LiteLLM, never stored)      |

---

## Security

- **Detection-only.** Requests and responses pass through untouched.
- **Provider keys are never written to the log store.** Saved keys live in an
  encrypted vault and are only decrypted in memory to forward a request.
- **Secrets/PII are redacted** before any text or tool-call arguments are stored.
- Run the proxy on an encrypted volume and set a high-entropy `CALUS_SECRET`.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[GNU AGPL-3.0](LICENSE). Running a modified version as a network service requires
publishing your source. For a commercial license without the AGPL obligations,
contact **Wholesphere**.
