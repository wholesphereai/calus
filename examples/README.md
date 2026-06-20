# Examples

## `chat_agent.py` — a GTM agent through Calus

A real **go-to-market (GTM) agent** — a B2B SaaS strategist for Wholesphere/Calus —
that talks to **Groq via the Calus proxy**. It helps with ICP, lead qualification,
cold outreach, and pricing; it keeps conversation memory and has two tools
(`qualify_lead`, `calus_pricing`), so you can watch agent traffic and tool calls
appear live in the dashboard.

```bash
# proxy running on :8000, dashboard on :5173
python examples/chat_agent.py               # interactive (Groq key auto-loaded from proxy/.env)
python examples/chat_agent.py --demo        # scripted run
```

Try: _"Who's our ICP?"_, _"Qualify a 3,000-person fintech running AI agents, high
budget."_, _"Draft a cold email to their CISO."_, _"What's our pricing?"_

The only Calus-specific line is `base_url="http://localhost:8000/v1"` — everything
else is an ordinary OpenAI-SDK app. Open http://localhost:5173 (Agents → `gtm-agent`)
to see its calls and tool calls. Detection-only: nothing is blocked. (Heads-up: a
GTM agent for a *security* product talks about attacks/OWASP a lot, so Calus will
flag some of its messages — that's the detector working, not a problem.)

### Two kinds of "memory"

- **The agent's conversation memory** lives in the `messages` list in the script —
  it's why the bot can answer "what did I just ask you?".
- **The proxy's store** is `proxy/calus_proxy.db` (SQLite): every scanned call's
  verdict, agent, tools, tool-calls, and *redacted* text. This is what the dashboard
  reads. Provider keys are never stored. Reset it by stopping the proxy and deleting
  the file (a fresh one is created on next start).
