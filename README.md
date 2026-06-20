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

---

## Quick start — Docker (recommended)

```bash
git clone https://github.com/wholesphereai/calus.git
cd calus
cp proxy/.env.example proxy/.env     # set CALUS_ADMIN_TOKEN + your provider keys
docker compose up --build
```

- Dashboard → http://localhost:5173 (paste the `CALUS_ADMIN_TOKEN` from `proxy/.env`)
- Proxy     → http://localhost:8000

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
cp .env.example .env          # edit: admin token + provider keys
python -m uvicorn calus_proxy.main:app --port 8000

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

## Configuration (`proxy/.env`)

| Variable               | Default              | Meaning                                            |
|------------------------|----------------------|----------------------------------------------------|
| `CALUS_ADMIN_TOKEN`    | _(generated)_        | Token the dashboard/API must present               |
| `CALUS_CORS_ORIGINS`   | `http://localhost:5173` | Allowed dashboard origins                       |
| `CALUS_DB_PATH`        | `calus_proxy.db`     | SQLite log store path                              |
| `CALUS_REDACT_STORE`   | `1`                  | Redact secrets/PII before storing                  |
| `CALUS_STORE_TEXT`     | `1`                  | Store redacted prompt/response preview             |
| `CALUS_SCAN_RESPONSES` | `1`                  | Also scan model responses                          |
| `CALUS_FLAG_THRESHOLD` | `0.5`                | Confidence at/above which a call is flagged         |
| `CALUS_SECRET`         | _(admin token)_      | Master secret for the encrypted key vault          |
| `OPENAI_API_KEY`, `GROQ_API_KEY`, … | —       | Upstream keys (read by LiteLLM, never stored)      |

---

## Benchmark — AgentDojo

Measure detection against [AgentDojo](https://github.com/ethz-spylab/agentdojo)
(ETH Zurich) prompt-injection attacks:

```bash
python -m calus.benchmark.external.agentdojo.build    # generate the test set
python -m calus.benchmark.harness --dataset agentdojo # score the engine
```

Reference (bundled set, 108 injections + 20 benign): **recall ≈ 73% / precision
≈ 97%** at the default verdict, up to **95% recall** at `confidence ≥ 0.20`. Add
`--live` (after `pip install agentdojo`) to score the current upstream suite. See
[`calus/benchmark/external/agentdojo`](calus/benchmark/external/agentdojo).

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
