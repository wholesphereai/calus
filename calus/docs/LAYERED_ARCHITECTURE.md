# Calus — Layered Architecture (Layer 1 + Layer 2 + Decision-Maker)

Calus is a **deterministic AI-agent security gateway**. Every layer only *observes*
and emits a **signal**; a single deterministic **decision-maker** is the only thing
that can block. The whole deterministic path (Layer 1 + Layer 2 + decision-maker)
runs in **milliseconds**, in-memory, with no I/O in the hot path.

```
                         ┌──────────────────────────────────────────┐
 input + agent context ─▶│ Layer 1  Pattern fast-path                 │ signal
                         │   known-attack patterns (regex + decoders  │──────┐
                         │   + lexical similarity), by taxonomy surface│      │
                         └──────────────────────────────────────────┘      │
                         ┌──────────────────────────────────────────┐      │
                         │ Layer 2  Capability-Flow Graph (PRIORITY)  │ signal│
                         │   taint(origin) × capability(sink, tiered) │──────┤
                         │   forbidden edge: untrusted → RED sink      │      │
                         └──────────────────────────────────────────┘      │
                         ┌──────────────────────────────────────────┐      │
                         │ Layer 3  Model  (HOOK ONLY — not built)    │ signal│
                         │   consulted ONLY on uncertain + HIGH-conseq │──────┤
                         └──────────────────────────────────────────┘      │
                                                                            ▼
                         ┌──────────────────────────────────────────────────────┐
                         │ DECISION-MAKER (deterministic, no data/model)          │
                         │   any block-signal + HIGH consequence → block          │
                         │   block-signal     + LOW  consequence → flag + log     │
                         │   no block-signal                     → pass           │
                         │   two-step escalation on uncertainty; safe-default      │
                         └──────────────────────────────────────────────────────┘
```

## Signals

Every layer emits only:

```
Signal { verdict: block | pass | uncertain,
         confidence: high | medium | low,
         surface: <taxonomy surface>,
         consequence: high | low,
         reasons[], owasp_llm[], owasp_agentic[], cwe[] }
```

No layer ever blocks. The decision-maker applies fixed rules to the signals.

## The decision rules (the only blocker)

1. A **HIGH-confidence** signal decides immediately. A **MEDIUM/uncertain** signal
   escalates to the next **different-in-kind** layer (patterns → flow graph → model)
   and is re-checked before any decision.
2. Once resolved:
   - any **block-signal + HIGH consequence → block**
   - **block-signal + LOW consequence → flag + log**
   - **no block-signal → pass**
3. Still uncertain after escalation: **HIGH consequence → block** (safe default);
   **LOW consequence → flag + allow**.

**Consequence** is HIGH only when a **RED-tier action is actually pending** (the
agent is about to do something irreversible/external). Merely *having* a powerful
tool in the toolset is not high-consequence on its own — otherwise every benign
turn would safe-default to block. Latent "untrusted content + RED capability in
reach" posture (Rule-of-Two) is surfaced as a **flag**, not a block; the block
happens when the RED action is attempted.

## Layer 2 — Capability-Flow Graph

Derived **entirely** from `agent-security-taxonomy.md` (no rule invented outside
it). Technique (taint-tracking, capability metadata, forbidden edges, tiering) is
borrowed from CaMeL, Microsoft FIDES, Meta's "Agents Rule of Two", NIST agentic
guidance and IFC literature — but applied to **our 16 taxonomy surfaces**.

- **Sources (taint origin):** `direct_prompt` is **trusted** (the principal);
  `web_content`, `tool_response`, `rag_vector_store`, `filesystem_read`,
  `email_calendar`, `memory_state`, `a2a`, `mcp_tool_call`, `skill_plugin` are
  **untrusted-origin**.
- **Sinks (tiered):** **RED** = `os_command_exec`, `filesystem_write`, `database`
  (write/delete/mass-read), `network_http`, `identity_secrets`,
  `payments_commerce`, `email_calendar` (send), `memory_state` (write), `a2a`
  (delegate), `skill_plugin` (load), `mcp_tool_call`. **LOW** = `web_content`,
  `rag_vector_store`, `filesystem_read` (ordinary). Resource-aware: a read whose
  target looks like a secret (`.env`, `id_rsa`, …) promotes to RED; a read-only DB
  query stays LOW.
- **Forbidden edge:** `untrusted-origin → RED sink` is blocked **unless** the flow
  passed an explicit sanitize/allow node. LOW-tier flows and trusted origins pass.
  This is deliberately **tiered to preserve utility** — blocking *all* untrusted →
  tool destroys task completion (CaMeL strict mode drops to ~67%).

See `calus/taxonomy/taxonomy.py` for the single source of truth, and run the
forbidden-edge table renderer in the tests for the full 9×11 matrix.

## Layer 3 — model hook (NOT built here)

The trained guard model lives and trains separately. `calus.register_model_layer`
registers a `(text, context) -> Signal | None` hook. The decision-maker consults
it **only** on genuinely uncertain + HIGH-consequence cases — most traffic never
touches it.

**Security invariant:** a jailbroken/compromised Layer 3 can only *emit a signal*.
It can never block or unblock on its own — it can only push a decision *toward*
block, never rescue something the deterministic layers blocked. The deterministic
decision-maker always holds.

## Enforcement modes (proxy)

- **verdict-mode (default):** detection-only. The decision is returned in
  `x-calus-action` / `x-calus-consequence` / `x-calus-decision-layers` headers; the
  request is never stopped.
- **gateway-block (opt-in, `CALUS_ENFORCE_MODE=gateway`):** a BLOCK decision stops
  the request — 403 on a blocked input, or replaces a response whose tool-call
  forms a forbidden edge.

---

## Threat model & boundary (read this — we do not overclaim)

Calus defends against **injected / untrusted-content attacks**: malicious
instructions or payloads that reach the agent through content it did not author —
**web pages, tool responses, RAG documents, MCP tool descriptions/responses, read
files, incoming email/calendar invites, persisted memory, and other agents (A2A)**.
This is the indirect-prompt-injection / goal-hijack / tool-poisoning threat class
(OWASP LLM01, OWASP Agentic ASI01–ASI05) — the attacks that turn an agent's own
capabilities against its user.

**Calus does NOT defend against a user deliberately misusing their own agent.**
The user is the principal: `direct_prompt` is trusted, and a user instructing their
own agent to run code, send mail, or spend money is an *authorized* action, not an
attack Calus blocks. (User-authored jailbreak *patterns* are still detected by
Layer 1 and surfaced, but the flow graph does not treat the user as an adversarial
content source.) Defending a system against its own operator is a **different threat
model** — abuse/misuse policy, authentication, and authorization — and is out of
scope for the capability-flow graph.

In short: **Calus stops the web page / tool / document from hijacking the agent. It
does not stop the operator from using the agent they control.**

### Taint assignment is fail-safe

The flow graph rests entirely on correct origin/taint labeling, so the labeling is
**fail-safe by construction**:

- A surface is **trusted only if it is *explicitly* `direct_prompt`** (the single
  `Taint.TRUSTED` entry in the taxonomy). There is no other trusted source.
- **Anything else is untrusted** — every known external surface (`tool_response`,
  `web_content`, `rag_vector_store`, `filesystem_read`, `email_calendar`,
  `memory_state`, `a2a`, `mcp_tool_call`, `skill_plugin`) *and* any unknown,
  unlabeled, mistyped, or empty origin. Unknown ⇒ untrusted, never trusted.
- This is enforced in one place — `is_trusted()` in `calus/taxonomy/taxonomy.py` —
  and consumed by `is_forbidden()` and `AgentContext.is_untrusted`. An unrecognized
  origin therefore *cannot* slip past the forbidden-edge check by being mistaken
  for the user prompt.

In the proxy, origin is assigned by `_origin_of()`:
1. explicit `x-calus-origin` / `x-calus-surface` header (lets apps declare
   web_content / rag_vector_store / mcp_tool_call / a2a / …), else
2. message role of the newest input turn: `tool`/`function` → `tool_response`
   (untrusted); a genuine `user` turn → `direct_prompt` (trusted), else
3. **fail-safe fallback → `unknown` (untrusted).**

**Caveat — RAG-stuffing inside a user turn.** The one way to *mislabel* untrusted
content as trusted is for the calling app to paste retrieved/external text *into a
`user`-role message* without a label. The proxy sees role=user and trusts it.
Mitigation: keep external content in `tool`/`system` turns, or set `x-calus-origin`
(e.g. `rag_vector_store`). The proxy cannot infer taint a caller hides inside a
user turn — this is an integration requirement, documented here so we don't
overclaim. In the normal agent loop (retrieval returns a `tool` message), taint is
assigned correctly and automatically.
