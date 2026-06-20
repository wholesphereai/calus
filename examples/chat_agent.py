"""
A GTM (go-to-market) agent that talks to Groq **through the Calus proxy** — proof
that the drop-in gateway works with a real, useful agent.

It's a go-to-market strategist for Wholesphere (makers of Calus): positioning, ICP,
lead qualification, cold outreach, pricing, and objection handling. It keeps
conversation memory and has two real tools (`qualify_lead`, `calus_pricing`), so you
can watch agent traffic and tool calls show up live in the Calus console.

Run (proxy on :8000, dashboard on :5173):
    python examples/chat_agent.py            # interactive chat
    python examples/chat_agent.py --demo     # scripted run (no typing)

The Groq key is read from proxy/.env automatically. Detection-only: nothing blocked.
"""
import os
import json
import argparse
from openai import OpenAI

# Convenience: load the proxy's .env so GROQ_API_KEY just works without exporting it.
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", "proxy", ".env"))
except Exception:
    pass

PROXY = os.environ.get("CALUS_PROXY_URL", "http://localhost:8000/v1")
MODEL = os.environ.get("CHAT_MODEL", "groq/llama-3.1-8b-instant")
API_KEY = os.environ.get("GROQ_API_KEY") or os.environ.get("OPENAI_API_KEY") or "set-GROQ_API_KEY"

client = OpenAI(base_url=PROXY, api_key=API_KEY)   # <-- the one line that routes via Calus

SYSTEM = (
    "You are a sharp B2B SaaS go-to-market (GTM) strategist embedded at Wholesphere, "
    "the maker of Calus — a drop-in AI-security gateway that gives teams threat "
    "detection, agent/tool observability, and OWASP LLM Top 10 coverage with no code "
    "changes. You help with positioning, ideal customer profile (ICP), lead "
    "qualification, cold outreach, pricing, demos, and objection handling. Be concrete, "
    "concise, and action-oriented. Use the qualify_lead tool to score prospects and the "
    "calus_pricing tool when pricing comes up. Speak like a seasoned GTM operator."
)

TOOLS = [
    {"type": "function", "function": {
        "name": "qualify_lead",
        "description": "Score a sales lead and recommend a sales motion.",
        "parameters": {"type": "object", "properties": {
            "company_size": {"type": "string", "enum": ["smb", "mid", "enterprise"]},
            "uses_ai_agents": {"type": "boolean"},
            "budget_band": {"type": "string", "enum": ["low", "med", "high"]},
        }, "required": ["company_size", "uses_ai_agents", "budget_band"]},
    }},
    {"type": "function", "function": {
        "name": "calus_pricing",
        "description": "Return Calus pricing tiers and what each includes.",
        "parameters": {"type": "object", "properties": {}},
    }},
]


def qualify_lead(company_size="smb", uses_ai_agents=False, budget_band="low", **_):
    score = {"smb": 15, "mid": 30, "enterprise": 45}.get(company_size, 10)
    score += 30 if uses_ai_agents else 5
    score += {"low": 5, "med": 15, "high": 25}.get(budget_band, 5)
    tier = "Hot" if score >= 70 else "Warm" if score >= 45 else "Cold"
    motion = ("Enterprise (AE + security champion)" if company_size == "enterprise"
              else "Sales-assisted" if score >= 45 else "Self-serve / PLG")
    return {"score": score, "tier": tier, "recommended_motion": motion,
            "why": f"{company_size} segment, AI agents={uses_ai_agents}, budget={budget_band}"}


def calus_pricing(**_):
    return {
        "Free": {"price": "$0", "for": "individuals & evals",
                 "includes": ["1 proxy", "7-day log retention", "community support"]},
        "Pro": {"price": "$499/mo", "for": "startups & teams",
                "includes": ["unlimited agents", "encrypted key vault", "90-day retention", "email support"]},
        "Enterprise": {"price": "custom", "for": "regulated / large orgs",
                       "includes": ["SSO/SAML", "SIEM export", "on-prem/VPC", "SLA + dedicated CSM"]},
    }


TOOL_FNS = {"qualify_lead": qualify_lead, "calus_pricing": calus_pricing}


def run_tool(name: str, raw_args: str) -> str:
    try:
        args = json.loads(raw_args or "{}")
    except Exception:
        args = {}
    fn = TOOL_FNS.get(name)
    return json.dumps(fn(**args)) if fn else json.dumps({"error": "unknown tool"})


def chat_once(messages: list) -> str:
    """One turn, with a tool-call round-trip if the model asks for one."""
    resp = client.chat.completions.create(model=MODEL, messages=messages,
                                          tools=TOOLS, user="gtm-agent")
    msg = resp.choices[0].message
    if msg.tool_calls:
        messages.append(msg.model_dump())                      # assistant's tool-call turn
        for tc in msg.tool_calls:
            result = run_tool(tc.function.name, tc.function.arguments)
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
        resp = client.chat.completions.create(model=MODEL, messages=messages, user="gtm-agent")
        msg = resp.choices[0].message
    messages.append({"role": "assistant", "content": msg.content})
    return msg.content or ""


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true", help="run a scripted conversation and exit")
    a = ap.parse_args(argv)

    messages = [{"role": "system", "content": SYSTEM}]
    print(f"GTM agent -> {MODEL} via Calus ({PROXY})")
    print("Ask about ICP, leads, outreach, pricing... ('exit' to quit)\n")

    if a.demo:
        script = [
            "In two sentences, who should we target for Calus and why?",
            "Qualify this lead: a 3,000-person fintech that runs AI agents, high budget.",
            "Draft a 3-line cold email to their CISO opening with a security hook.",
            "What's our pricing?",
            "What did I say the prospect's industry was?",   # tests memory
        ]
        for user in script:
            print(f"you> {user}")
            messages.append({"role": "user", "content": user})
            print(f"gtm> {chat_once(messages)}\n")
        return 0

    while True:
        try:
            user = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if user.lower() in ("exit", "quit", ""):
            break
        messages.append({"role": "user", "content": user})
        print(f"gtm> {chat_once(messages)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
