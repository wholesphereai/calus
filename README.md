<div align="center">

<img src="assets/logo.png" alt="Calus" width="104" />

# Calus

**A drop-in AI-security gateway. No code changes. No SDK.**

Calus sits between your AI tools and the model providers. It gives you threat
detection, agent and tool-call observability, and OWASP LLM Top 10 coverage on
every call. Detection-only: it observes and flags, it never blocks or alters
your traffic.

</div>

---

## Benchmark coverage

Calus ships with **27,871 detection patterns** across **41 rule packs**, mapped to
the **OWASP LLM Top 10 (2025)**. It is a prompt-injection and jailbreak-pattern
detection gateway: it flags adversarial *inputs* (injection wrappers, jailbreak
templates, obfuscation) before they reach the model. Every number below is scored
by the real engine against held-out, third-party academic benchmarks, with no
tuning. Reproduce any row with the commands in [`calus/benchmark`](calus/benchmark).

> **False-positive rate on normal traffic: 0.90%.** On 2,000 ordinary user
> messages (Databricks Dolly-15k, held out from calibration), Calus's default
> verdict flags only 0.90%. That is the number that matters for production. The
> tables below report both the default verdict (the production operating point)
> and `conf >= 0.20`, the higher-recall operating point where the engine flags any
> input whose detection-confidence score reaches 0.20.

### 1. Prompt injection (core threat model)

| Benchmark | Setting | Recall | Precision | F1 |
|---|---|:--:|:--:|:--:|
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) · NeurIPS 2024 | default | 82% | **100%** | 90% |
| | conf >= 0.20 | **95%** | 93% | **94%** |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) · ACL 2024, Standard | default | 35% | 99% | 52% |
| | conf >= 0.20 | 69% | 99% | 82% |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) · ACL 2024, Enhanced | default | **100%** | 99% | **100%** |
| | conf >= 0.20 | **100%** | 99% | **99%** |

The Standard split contains subtle injections with no recognizable wrapper. The
Enhanced setting prepends explicit hacking-prompt syntax that the pattern tier
catches reliably, which is also how real-world indirect injection typically
arrives. So Enhanced (Calus catches 100% of its 1,054 injected tool responses at
the default verdict, 99.5% precision) is the more representative number. By attack
type at `conf >= 0.20`: data-exfiltration F1 93%, direct-harm F1 66%. The gap is
because direct-harm payloads tend to be shorter, less-structured commands that
carry fewer recognizable injection signatures than the more elaborate
exfiltration chains.

### 2. Jailbreak detection (JailbreakBench artifacts, NeurIPS 2024)

Scored against the real jailbreak attack strings in JailbreakBench's artifact
library, with the 100 benign JBB behaviors as the false-positive control. Default
verdict shown (precision-led):

| Attack family | Recall | Precision | F1 |
|---|:--:|:--:|:--:|
| JBC, manual templates (AIM / DAN-style) | **100%** | 98% | 99% |
| PAIR, LLM-crafted adaptive jailbreaks | 29% | 97% | 45% |
| GCG, adversarial suffix (filter-evasion) | 29% | 94% | 44% |
| **All families combined** | 45% | 99% | 62% |

Calus catches every classic manual jailbreak template at 98% precision. Adaptive
(PAIR) and gibberish-suffix (GCG) attacks, which are explicitly designed to evade
pattern filters, are caught partially and at high precision.

### 3. Scope boundary (harmful-intent corpora)

[AdvBench](https://github.com/llm-attacks/llm-attacks) (520 prompts) and
[HarmBench](https://github.com/centerforaisafety/HarmBench) (200 standard
behaviors) measure whether a bare request carries harmful intent
("write a tutorial on ..."). That is content moderation, a different layer from
injection and jailbreak detection. Calus is not a content classifier; it flags
only the subset of these prompts that carry an injection or obfuscation signature,
so recall is low by design:

| Benchmark | Recall (default) | Recall (conf >= 0.20) |
|---|:--:|:--:|
| AdvBench, 520 harmful goals | 3% | 28% |
| HarmBench, 200 standard behaviors | 11% | 47% |

For harmful-content blocking, pair Calus with a content-moderation classifier.
Calus owns the injection and jailbreak layer those classifiers miss.

```bash
# Build any test set, then score the real engine (one input per line):
python -m calus.benchmark.external.injecagent.build
python -m calus.benchmark.harness --dataset injecagent      # also: agentdojo,
                                                            # jailbreakbench, advbench, harmbench
```

Methodology, sources, and per-split numbers:
[`calus/benchmark/README.md`](calus/benchmark/README.md).

---

## What you get

- **Drop-in proxy.** Point any OpenAI-compatible app at Calus by setting one
  environment variable. No code changes, no SDK to install.
- **Multi-provider.** OpenAI, Groq, Anthropic, Gemini, Mistral, Cohere, and
  anything [LiteLLM](https://github.com/BerriAI/litellm) supports, selected by the
  `model` prefix.
- **Threat detection.** A tiered engine (regex, then lexical similarity, then
  optional semantic) flags prompt injection, jailbreaks, agent abuse, and more,
  mapped to the OWASP LLM Top 10 (2025).
- **Agent and tool observability.** Every agent, the tools it can call, and the
  tool calls it actually makes (arguments redacted) are traced in the console.
- **Secret and PII redaction.** Secrets and PII are masked before anything is
  stored.
- **Encrypted key vault.** Optionally save provider keys; stored encrypted at
  rest, shown masked, revealed on demand. Provider keys are never written to the
  call log.
- **Console.** A clean dashboard: Overview, Agents, Threats, Live calls, API keys,
  and Connect.

## Architecture

```
your app ──(your key)──▶  CALUS PROXY  ──(same key)──▶  OpenAI / Groq / Anthropic / ...
                              │
                       scan + log verdict
                     (key used in-flight, never stored)
                              │
                              ▼
                      CALUS DASHBOARD  (you watch live)
```

| Component | Path | What it is |
|---|---|---|
| Engine | `calus/` | Pure-Python detection library (`pip install -e calus`) |
| Proxy | `proxy/calus_proxy` | FastAPI OpenAI-compatible gateway and dashboard API |
| Dashboard | `dashboard/` | React + TypeScript (Vite) console |

```
calus/
├── README.md  LICENSE  SECURITY.md  CONTRIBUTING.md
├── Dockerfile  docker-compose.yml  .dockerignore
├── .github/workflows/        # ci, security, release
│
├── calus/                    # detection engine (Python package)
│   ├── pyproject.toml  api.py  cli.py  owasp.py
│   ├── detection/            # cascade engine, scored regex, similarity, redaction
│   ├── patterns/             # 27k+ OWASP-mapped rule packs
│   ├── learning/  context/  integrations/  tools/
│   ├── benchmark/            # accuracy harness + external benchmark sets
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
    └── src/  ( App, components, api, types, index.css )
```

> Installing dependencies takes about 1 to 2 minutes the first time. After that
> the proxy boots and warms its 27k-pattern engine in about 5 seconds, then scans
> in about 15 ms. No model downloads, no GPU.

---

## Quick start with Docker (recommended)

```bash
git clone https://github.com/wholesphereai/calus.git
cd calus
cp proxy/.env.example proxy/.env     # add your provider keys (admin token optional)
docker compose up --build
```

- Dashboard: http://localhost:5173
- Proxy: http://localhost:8000

**Admin token.** You do not have to set one. If `CALUS_ADMIN_TOKEN` is left blank,
the proxy auto-generates a token and prints it in the startup logs; copy that into
the dashboard. Set your own in `proxy/.env` only if you want it stable across
restarts.

## Quick start, local (no Docker)

```bash
git clone https://github.com/wholesphereai/calus.git
cd calus
python -m venv .venv && . .venv/Scripts/activate     # Windows
# source .venv/bin/activate                          # macOS / Linux

# 1) engine
python -m pip install -e calus

# 2) proxy (terminal 1)
cd proxy
python -m pip install -r requirements.txt
cp .env.example .env          # add provider keys; admin token auto-generates if blank
python -m uvicorn calus_proxy.main:app --port 8000   # prints the admin token on first run

# 3) dashboard (terminal 2)
cd dashboard
npm install
npm run dev                   # http://localhost:5173
```

---

## Point your app at Calus

One environment variable is all you need. Calus forwards every call with your own
provider key — used in-flight, never written to any log or store.

```bash
export OPENAI_BASE_URL="http://localhost:8000/v1"
# that's it — run your app as usual
```

The sections below show how to connect from each SDK, and how to name your agents
so their traffic shows up separately in the dashboard.

---

### Why name your agents?

Without a name, every call lands in the dashboard under **"unknown"** — one flat
stream with no way to tell which service sent what.

```
Dashboard (no name)           Dashboard (named)
─────────────────────         ──────────────────────────────
Agents                        Agents
  └─ unknown (47 calls)         ├─ customer-support  (31 calls)
                                ├─ search-agent      (12 calls)
                                └─ data-pipeline      (4 calls)
```

Name an agent one of two ways — they are equivalent, pick whichever fits your SDK:

| Method | How | Best for |
|---|---|---|
| `user` field | Standard OpenAI field, part of the request body | OpenAI SDK, any JSON client |
| `X-Calus-Agent` header | HTTP header, not part of the LLM payload | LangChain, frameworks where `user` isn't exposed |

---

### OpenAI Python SDK

**Without a name** — traffic appears as "unknown" in the dashboard:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="sk-your-own-key",
)

response = client.chat.completions.create(
    model="groq/llama-3.3-70b-versatile",
    messages=[{"role": "user", "content": "Hello"}],
)
```

**With a name** — use the `user` field; the agent appears by name in the Agents tab:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="sk-your-own-key",
)

response = client.chat.completions.create(
    model="groq/llama-3.3-70b-versatile",
    user="my-agent",                         # shows up as "my-agent" in the dashboard
    messages=[{"role": "user", "content": "Hello"}],
)
```

**With a name via header** — use `X-Calus-Agent` if you prefer headers or share one
client across agents:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="sk-your-own-key",
    default_headers={"X-Calus-Agent": "my-agent"},
)

response = client.chat.completions.create(
    model="groq/llama-3.3-70b-versatile",
    messages=[{"role": "user", "content": "Hello"}],
)
```

---

### OpenAI Node.js / TypeScript SDK

```typescript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://localhost:8000/v1",
  apiKey: "sk-your-own-key",
  defaultHeaders: { "X-Calus-Agent": "my-agent" },  // name in dashboard
});

const response = await client.chat.completions.create({
  model: "groq/llama-3.3-70b-versatile",
  messages: [{ role: "user", content: "Hello" }],
});
```

---

### LangChain (Python)

LangChain's `ChatOpenAI` doesn't expose the `user` body field directly, so use
`default_headers` instead:

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="groq/llama-3.3-70b-versatile",
    base_url="http://localhost:8000/v1",
    api_key="sk-your-own-key",
    default_headers={"X-Calus-Agent": "my-agent"},  # name in dashboard
)

response = llm.invoke("Hello")
```

**Without a name** (traffic appears as "unknown"):

```python
llm = ChatOpenAI(
    model="groq/llama-3.3-70b-versatile",
    base_url="http://localhost:8000/v1",
    api_key="sk-your-own-key",
)
```

---

### Claude Code

Route Claude Code's API calls through Calus by setting the environment variable
before launching it. Claude Code uses the Anthropic SDK internally, which is
OpenAI-compatible through Calus's LiteLLM layer.

**Without a name** (appears as "unknown" in dashboard):

```bash
export ANTHROPIC_BASE_URL="http://localhost:8000"
claude
```

**With a name via header** — add it to your `~/.claude/settings.json` or pass it
as an environment variable so every Claude Code session is tagged:

```bash
export ANTHROPIC_BASE_URL="http://localhost:8000"
export CALUS_AGENT_HEADER="claude-code"   # picked up by Calus
claude
```

Or configure it permanently in `~/.claude/settings.json`:

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://localhost:8000",
    "X-Calus-Agent": "claude-code"
  }
}
```

Once set, every prompt you send through Claude Code appears in the Calus dashboard
under **"claude-code"** with full threat scores and tool-call traces.

---

### curl

**Without a name:**

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer sk-your-own-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "groq/llama-3.3-70b-versatile",
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

**With a name via header:**

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer sk-your-own-key" \
  -H "Content-Type: application/json" \
  -H "X-Calus-Agent: my-agent" \
  -d '{
    "model": "groq/llama-3.3-70b-versatile",
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

**With a name via `user` field:**

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer sk-your-own-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "groq/llama-3.3-70b-versatile",
    "user": "my-agent",
    "messages": [{"role": "user", "content": "Hello"}]
  }'
```

---

### Reading the verdict from response headers

Every response from Calus carries three headers you can read in your app or pipe
into a SIEM — without touching the dashboard at all:

| Header | Values | Meaning |
|---|---|---|
| `x-calus-flagged` | `true` / `false` | Whether Calus flagged this call |
| `x-calus-confidence` | `0.00` – `1.00` | Detection confidence score |
| `x-calus-owasp` | e.g. `LLM01`, `LLM06` | OWASP LLM Top 10 category, if flagged |

```python
import requests

resp = requests.post(
    "http://localhost:8000/v1/chat/completions",
    headers={
        "Authorization": "Bearer sk-your-own-key",
        "X-Calus-Agent": "my-agent",
    },
    json={
        "model": "groq/llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": "Hello"}],
    },
)

print(resp.headers.get("x-calus-flagged"))     # "false"
print(resp.headers.get("x-calus-confidence"))  # "0.12"
print(resp.headers.get("x-calus-owasp"))       # "" or "LLM01"
```

The Connect tab in the dashboard has ready-to-paste snippets for every SDK.

---

## Add provider keys, three ways

You can let callers send their own key per request (BYOK, nothing stored), or save
keys in Calus's encrypted vault so you do not re-paste them. Saved keys are
encrypted at rest, shown masked, and used to forward upstream when a request does
not carry its own.

1. **Dashboard.** Open the API keys page: pick a provider, paste the key, Add.
   Reveal or delete any time.
2. **Command line** (same vault):
   ```bash
   cd proxy
   python -m calus_proxy.keys add --provider groq --key gsk_... --label prod
   python -m calus_proxy.keys list
   python -m calus_proxy.keys delete <id>
   ```
3. **Environment.** Put `OPENAI_API_KEY`, `GROQ_API_KEY`, and others in
   `proxy/.env` (read by LiteLLM, never stored in the log).

Resolution order when forwarding: caller's bearer key, then saved vault key, then
env key.

---

## Configuration (`proxy/.env`)

| Variable | Default | Meaning |
|---|---|---|
| `CALUS_ADMIN_TOKEN` | auto-generated and printed | Token the dashboard and API must present. Leave blank to auto-generate one at startup. |
| `CALUS_PROXY_TOKEN` | blank | Optional data-plane token. If set, `/v1/*` requires it. Leave blank only on a private network. |
| `CALUS_CORS_ORIGINS` | `http://localhost:5173` | Allowed dashboard origins. |
| `CALUS_DB_PATH` | `calus_proxy.db` | SQLite log store path. |
| `CALUS_REDACT_STORE` | `1` | Redact secrets and PII before storing. |
| `CALUS_STORE_TEXT` | `1` | Store redacted prompt and response preview. |
| `CALUS_SCAN_RESPONSES` | `1` | Also scan model responses. |
| `CALUS_FLAG_THRESHOLD` | `0.5` | Confidence at or above which a call is flagged. |
| `CALUS_SECRET` | admin token | Master secret for the encrypted key vault. |
| `OPENAI_API_KEY`, `GROQ_API_KEY`, ... | none | Upstream keys (read by LiteLLM, never stored). |

---

## Security

- **Detection-only.** Requests and responses pass through untouched.
- **Provider keys are never written to the log store.** Saved keys live in an
  encrypted vault and are only decrypted in memory to forward a request.
- **Secrets and PII are redacted** before any text or tool-call arguments are
  stored.
- Run the proxy on an encrypted volume and set a high-entropy `CALUS_SECRET`.
- **Securing the data plane.** `/v1/*` is unauthenticated by default so Calus
  stays drop-in. That is fine on localhost or a private network. If you expose the
  port, set `CALUS_PROXY_TOKEN`; callers must then present it (the
  `X-Calus-Proxy-Token` header or `Authorization: Bearer ...`, constant-time
  checked) or the request is rejected. Leaving it blank on a public port turns the
  proxy into an open relay that spends your stored provider keys.
- The verdict is surfaced inline via the `x-calus-flagged`, `x-calus-confidence`,
  and `x-calus-owasp` response headers, so a SIEM can act on it without the
  dashboard.

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[MIT](LICENSE). Use it freely, including in commercial and closed-source
products. Just keep the copyright and license notice.

---

<div align="center"><sub>Calus is built and maintained by Wholesphere.</sub></div>
