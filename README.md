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

Set one environment variable and run your app as usual. Calus forwards each call
with your own provider key (used in-flight, never stored):

```bash
export OPENAI_BASE_URL="http://localhost:8000/v1"
```

Or pass the base URL explicitly:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",   # route through Calus
    api_key="sk-your-own-key",
)
client.chat.completions.create(
    model="groq/llama-3.3-70b-versatile",   # any provider via prefix
    user="my-agent",                        # names this agent in the console
    messages=[{"role": "user", "content": "hello"}],
)
```

Name each agent with the OpenAI `user` field (or an `X-Calus-Agent` header) so its
traffic and tool calls show up separately. The Connect tab in the dashboard has
copy-paste snippets for the OpenAI SDK, Claude Code, LangChain, and curl.

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

[GNU AGPL-3.0](LICENSE). Running a modified version as a network service requires
publishing your source. For a commercial license without the AGPL obligations,
contact Wholesphere.

---

<div align="center"><sub>Calus is built and maintained by Wholesphere.</sub></div>
