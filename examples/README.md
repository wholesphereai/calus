# Examples

## `chat_agent.py` — a chat agent through Calus

A minimal OpenAI-SDK chat agent that talks to **Groq via the Calus proxy**. It keeps
conversation memory and has one tool (`calculate`), so you can watch agent traffic,
tool calls, and flagged messages appear live in the dashboard.

```bash
# proxy running on :8000, dashboard on :5173
export GROQ_API_KEY=gsk_...                 # your Groq key
python examples/chat_agent.py               # interactive
python examples/chat_agent.py --demo        # scripted run
```

The only Calus-specific line is `base_url="http://localhost:8000/v1"` — everything
else is an ordinary OpenAI-SDK app. Open http://localhost:5173 (Agents → `chat-agent`)
to see its calls, the `calculate` tool call, and any flagged prompts. Detection-only:
nothing is blocked.

### Two kinds of "memory"

- **The agent's conversation memory** lives in the `messages` list in the script —
  it's why the bot can answer "what did I just ask you?".
- **The proxy's store** is `proxy/calus_proxy.db` (SQLite): every scanned call's
  verdict, agent, tools, tool-calls, and *redacted* text. This is what the dashboard
  reads. Provider keys are never stored. Reset it by stopping the proxy and deleting
  the file (a fresh one is created on next start).
