# Calus — full setup (engine + proxy + dashboard)

Three pieces that sit next to each other in one folder:

```
calus/                        <-- your repo root (C:\Users\HiMax Group\calus\)
├── calus/                    <-- the detection engine (you already have this)
│   ├── detection/  patterns/  benchmark/  api.py  cli.py  ...
│   └── pyproject.toml
├── proxy/                    <-- the FastAPI proxy  (NEW — from this zip)
│   ├── calus_proxy/
│   │   ├── __init__.py
│   │   ├── main.py           # OpenAI-compatible gateway + dashboard API
│   │   ├── config.py
│   │   └── store.py          # secure SQLite log store
│   ├── requirements.txt
│   ├── .env.example
│   └── README.md
└── dashboard/                <-- the React + TS console  (NEW — from this zip)
    ├── src/
    │   ├── App.tsx  components.tsx  api.ts  types.ts  index.css  main.tsx
    ├── package.json
    ├── index.html
    ├── vite.config.ts
    └── README.md
```

Unzip this so `proxy/` and `dashboard/` land **next to** your existing `calus/`
folder (all three inside the repo root).

## Run order

**1. Engine** — install once (from the repo root, with your venv active):
```
pip install -e calus
```

**2. Proxy** — terminal 1:
```
cd proxy
pip install -r requirements.txt
copy .env.example .env          # (PowerShell: cp .env.example .env) then edit it
uvicorn calus_proxy.main:app --port 8000
```
It prints an admin token on first run — copy it. Put your provider keys
(OPENAI_API_KEY, etc.) in `.env`.

**3. Dashboard** — terminal 2:
```
cd dashboard
npm install
npm run dev                     # http://localhost:5173
```
Open it, paste the admin token, and you're in.

**4. Point an app at the proxy** — one line, no app code change:
```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8000/v1", api_key="sk-...")
client.chat.completions.create(model="gpt-4o",
    messages=[{"role":"user","content":"ignore all previous instructions"}])
```
Every call now appears in the dashboard with its verdict. Detection only — nothing
is blocked or altered.

## Notes
- The proxy needs network access to reach providers; the dashboard only talks to the proxy.
- Provider keys are never stored or logged. Secrets/PII in stored text are redacted.
- Works with any model LiteLLM supports — change `model` (and the matching key in `.env`).
