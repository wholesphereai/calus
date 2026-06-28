"""
calus.taxonomy.taxonomy — capability-flow graph nodes & edges, derived 1:1 from
`agent-security-taxonomy.md` (master table, section 2; impact levels, section 6).

Two roles a surface can play:

  * SOURCE  — a place content arrives FROM (a delivery channel). Each source has a
              taint: TRUSTED (the user / principal) or UNTRUSTED (web, tool output,
              RAG, MCP, file, email, memory, A2A, skills — anything the attacker can
              influence).
  * SINK    — a capability the agent can ACT through. Tiered RED (irreversible /
              external / high-consequence) vs LOW (read-only / observe), per the
              taxonomy's impact column.

A surface may be BOTH (e.g. `email_calendar` carries untrusted incoming mail AND
can send mail; `filesystem_read` carries untrusted file content AND is a read
sink). That duality is intentional and modeled explicitly.

Threat-model boundary (see docs): the trust of `direct_prompt` = TRUSTED encodes
that Calus defends against *injected / untrusted-content* attacks, NOT against a
user deliberately misusing their own agent. User jailbreaks are Layer 1's job.
"""
from __future__ import annotations
import re
from enum import Enum
from typing import Optional


class Taint(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    SANITIZED = "sanitized"


class Tier(str, Enum):
    RED = "RED"      # irreversible / external / costly -> HIGH consequence
    LOW = "LOW"      # read-only / observe / logging   -> LOW consequence


class Impact(str, Enum):
    OBSERVE = "observe"
    ACTION = "action"
    HIGH = "high_consequence"


# --------------------------------------------------------------------------- #
# The 16 surfaces. One dict, every attribute, no rule invented outside the
# taxonomy master table. `source` = taint if this surface delivers content (else
# None). `sink` = tier if the agent can act through it (else None).
# --------------------------------------------------------------------------- #
#
#   key                 source taint        sink tier   impact (default)
#
SURFACE: dict[str, dict] = {
    "direct_prompt": {
        "source": Taint.TRUSTED, "sink": None, "impact": Impact.OBSERVE,
        "owasp_llm": ["LLM01"], "owasp_agentic": ["ASI01"], "cwe": ["CWE-77"],
        "desc": "user instructions (the principal)",
    },
    "mcp_tool_call": {
        "source": Taint.UNTRUSTED, "sink": Tier.RED, "impact": Impact.HIGH,
        "owasp_llm": ["LLM01"], "owasp_agentic": ["ASI04", "ASI07"],
        "cwe": ["CWE-94", "CWE-829"],
        "desc": "external tool invocation via MCP (poisoned descriptions/responses)",
    },
    "tool_response": {
        "source": Taint.UNTRUSTED, "sink": None, "impact": Impact.OBSERVE,
        "owasp_llm": ["LLM01"], "owasp_agentic": ["ASI01"], "cwe": ["CWE-20"],
        "desc": "data returned by a called tool (indirect injection)",
    },
    "rag_vector_store": {
        "source": Taint.UNTRUSTED, "sink": Tier.LOW, "impact": Impact.OBSERVE,
        "owasp_llm": ["LLM01", "LLM08"], "owasp_agentic": ["ASI01"], "cwe": ["CWE-20"],
        "desc": "retrieved documents (poisoned retrieval / embedding injection)",
    },
    "web_content": {
        "source": Taint.UNTRUSTED, "sink": Tier.LOW, "impact": Impact.OBSERVE,
        "owasp_llm": ["LLM01"], "owasp_agentic": ["ASI01"], "cwe": ["CWE-79"],
        "desc": "browsed page content (indirect injection / hidden instructions)",
    },
    "filesystem_read": {
        "source": Taint.UNTRUSTED, "sink": Tier.LOW, "impact": Impact.OBSERVE,
        "owasp_llm": ["LLM02", "LLM06"], "owasp_agentic": ["ASI03"],
        "cwe": ["CWE-22", "CWE-200"],
        "desc": "read local files (path traversal, secret-read promotes to RED)",
    },
    "filesystem_write": {
        "source": None, "sink": Tier.RED, "impact": Impact.HIGH,
        "owasp_llm": ["LLM06"], "owasp_agentic": ["ASI07"],
        "cwe": ["CWE-73", "CWE-552"],
        "desc": "write/modify/delete files (configs, payloads, destructive delete)",
    },
    "os_command_exec": {
        "source": None, "sink": Tier.RED, "impact": Impact.HIGH,
        "owasp_llm": ["LLM06"], "owasp_agentic": ["ASI06", "ASI07"],
        "cwe": ["CWE-78", "CWE-94"],
        "desc": "run commands on host (RCE, command injection, rm -rf)",
    },
    "database": {
        "source": None, "sink": Tier.RED, "impact": Impact.HIGH,
        "owasp_llm": ["LLM06", "LLM08"], "owasp_agentic": ["ASI07"],
        "cwe": ["CWE-89", "CWE-200"],
        "desc": "query/write DB (SQLi, mass read, unauthorized write/delete)",
    },
    "network_http": {
        "source": None, "sink": Tier.RED, "impact": Impact.HIGH,
        "owasp_llm": ["LLM06"], "owasp_agentic": ["ASI07"], "cwe": ["CWE-918"],
        "desc": "outbound requests (SSRF, exfiltration, internal endpoints)",
    },
    "identity_secrets": {
        "source": None, "sink": Tier.RED, "impact": Impact.HIGH,
        "owasp_llm": ["LLM02", "LLM06"], "owasp_agentic": ["ASI03"],
        "cwe": ["CWE-522", "CWE-798"],
        "desc": "API keys / tokens / OAuth (credential leak, secret exfiltration)",
    },
    "email_calendar": {
        "source": Taint.UNTRUSTED, "sink": Tier.RED, "impact": Impact.HIGH,
        "owasp_llm": ["LLM01", "LLM06"], "owasp_agentic": ["ASI01", "ASI07"],
        "cwe": ["CWE-20"],
        "desc": "incoming mail/invite (injection); send mail = RED external send",
    },
    "payments_commerce": {
        "source": None, "sink": Tier.RED, "impact": Impact.HIGH,
        "owasp_llm": ["LLM06"], "owasp_agentic": ["ASI06"], "cwe": ["CWE-840"],
        "desc": "spend money / place orders (unauthorized spend, overspend)",
    },
    "memory_state": {
        "source": Taint.UNTRUSTED, "sink": Tier.RED, "impact": Impact.HIGH,
        "owasp_llm": ["LLM01"], "owasp_agentic": ["ASI02"], "cwe": ["CWE-20"],
        "desc": "persistent memory (poisoning); write = RED (persists across turns)",
    },
    "a2a": {
        "source": Taint.UNTRUSTED, "sink": Tier.RED, "impact": Impact.HIGH,
        "owasp_llm": ["LLM01"], "owasp_agentic": ["ASI05"], "cwe": ["CWE-94"],
        "desc": "agent-to-agent (session smuggling); delegation = RED (rogue agent)",
    },
    "skill_plugin": {
        "source": Taint.UNTRUSTED, "sink": Tier.RED, "impact": Impact.HIGH,
        "owasp_llm": ["LLM03"], "owasp_agentic": ["ASI04"], "cwe": ["CWE-829"],
        "desc": "load skills/plugins (malicious skill, typosquat, supply chain)",
    },
}

SURFACES: tuple[str, ...] = tuple(SURFACE.keys())


# --------------------------------------------------------------------------- #
# Derived lookups (built once at import — pure dict reads in the hot path).
# --------------------------------------------------------------------------- #
_SOURCE_TAINT: dict[str, Taint] = {
    k: v["source"] for k, v in SURFACE.items() if v["source"] is not None
}
_SINK_TIER: dict[str, Tier] = {
    k: v["sink"] for k, v in SURFACE.items() if v["sink"] is not None
}


def source_taint(surface: str) -> Optional[Taint]:
    """Taint of content arriving via `surface`, or None if not a delivery channel."""
    return _SOURCE_TAINT.get(surface)


def sink_tier(surface: str) -> Optional[Tier]:
    """Capability tier of `surface` as a sink, or None if not an action surface."""
    return _SINK_TIER.get(surface)


def is_source(surface: str) -> bool:
    return surface in _SOURCE_TAINT


def is_sink(surface: str) -> bool:
    return surface in _SINK_TIER


def is_trusted(origin: str) -> bool:
    """A surface is TRUSTED only if it is explicitly labeled Taint.TRUSTED in the
    taxonomy — currently ONLY `direct_prompt` (the user/principal). Every other
    value — a known untrusted surface, an unknown surface, a typo, or "" — is NOT
    trusted. This is the single fail-safe gate the whole flow graph rests on."""
    return SURFACE.get(origin, {}).get("source") is Taint.TRUSTED


def is_forbidden(origin: str, sink: str, sanitized: bool = False) -> bool:
    """The core rule: untrusted-origin -> RED-tier sink is forbidden UNLESS the
    flow passed through a sanitize/allow node. LOW-tier sinks and the trusted user
    prompt are permitted to preserve utility.

    FAIL-SAFE: an origin is treated as untrusted unless it is *explicitly* trusted,
    so an unknown / unrecognized / unlabeled origin can never bypass the check by
    being mistaken for the trusted user prompt."""
    if sanitized:
        return False
    return (not is_trusted(origin)) and _SINK_TIER.get(sink) is Tier.RED


def forbidden_edges() -> list[tuple[str, str]]:
    """Full cross-product of forbidden (untrusted-source -> RED-sink) edges. Used
    to render the sanity-check table and to assert coverage in tests."""
    srcs = [s for s, t in _SOURCE_TAINT.items() if t is Taint.UNTRUSTED]
    snks = [s for s, t in _SINK_TIER.items() if t is Tier.RED]
    return [(a, b) for a in srcs for b in snks]


# --------------------------------------------------------------------------- #
# Action classifier: map a concrete tool/function name (and optional argument
# text) to a taxonomy SINK surface + tier. Deterministic keyword routing — no I/O,
# no ML. This is how Layer 2 turns "the agent is about to call `send_email`" into
# "RED sink: email_calendar (external send)".
#
# Order matters: the first matching rule wins, most-dangerous first. Resource-aware
# refinements (secret-path read -> RED; scoped DB read -> LOW) are applied after.
# --------------------------------------------------------------------------- #
_SECRET_HINTS = (
    ".env", "id_rsa", "id_ed25519", "authorized_keys", ".ssh", "credentials",
    "secret", "secrets", "api_key", "apikey", "api-key", "token", "password",
    "passwd", "shadow", ".aws", ".npmrc", ".pypirc", "mcp.json", ".git-credentials",
    "private_key", "privatekey", "keystore", ".pem",
)

# (sink_surface, default_tier, keywords). Matching is TOKEN-AWARE, not raw
# TOKEN-aware (NOT substring): a single-word keyword must equal a whole token of
# the tool name (so "stat" does NOT match "...LightState", "cat" does NOT match
# "frobnicate"); a multi-word keyword (e.g. "send_email", "grant_access") must
# appear as a CONTIGUOUS run of tokens. Tokens come from camelCase + separator
# splitting. Unknown tools fall through to None. Order: most-dangerous first.
#
# Physical/device actuation (unlock, dispatch, grant access) maps to os_command_exec
# as the nearest RED "system/host action" sink — the taxonomy has no dedicated
# IoT-actuation surface; the forbidden-edge rule only needs RED vs LOW.
_ACTION_RULES: list[tuple[str, Tier, tuple[str, ...]]] = [
    ("os_command_exec",   Tier.RED, ("exec", "execute", "shell", "bash", "sh", "cmd", "run",
                                     "command", "run_code", "runcode", "subprocess", "spawn",
                                     "eval", "interpreter", "powershell", "terminal", "popen",
                                     # physical / device control (B2: InjecAgent direct-harm)
                                     "unlock", "grant_access", "guest_access", "actuate",
                                     "dispatch")),
    ("payments_commerce", Tier.RED, ("pay", "payment", "payout", "charge", "checkout",
                                     "purchase", "order", "refund", "invoice", "billing",
                                     "stripe", "transaction", "wire", "transfer",
                                     # B2: financial transactions (Binance/Venmo/Bank harm)
                                     "withdraw", "deposit", "trade")),
    ("identity_secrets",  Tier.RED, ("secret", "credential", "vault", "get_token", "read_key",
                                     "api_key", "apikey", "oauth", "keychain", "keystore",
                                     "private_key", "secrets",
                                     # B2: credential/2FA tampering & impersonation
                                     "two_factor", "2fa", "auto_fill", "share_password",
                                     "sharepassword", "share_data", "deepfake")),
    ("network_http",      Tier.RED, ("http", "https", "url", "curl", "webhook", "upload",
                                     "egress", "ssrf", "exfil", "outbound", "post_request",
                                     "send_request")),
    # memory_state BEFORE filesystem_write/database so "write_memory" /
    # "update_memory" route to memory poisoning (ASI02), not the generic verb rules.
    ("memory_state",      Tier.RED, ("write_memory", "save_memory", "store_memory", "set_memory",
                                     "update_memory", "remember", "memorize", "persist")),
    ("filesystem_write",  Tier.RED, ("write_file", "writefile", "write", "delete_file",
                                     "deletefile", "modify_file", "save_file", "put_file",
                                     "edit_file", "append_file", "overwrite", "unlink",
                                     "rmdir", "mkdir", "rm")),
    ("database",          Tier.RED, ("sql", "db", "insert", "update", "delete", "drop",
                                     "truncate", "alter", "upsert", "grant", "mysql", "psql",
                                     "postgres", "mongo", "redis", "sqlite", "execute_query")),
    ("email_calendar",    Tier.RED, ("send_email", "sendmail", "send_mail", "smtp", "send",
                                     "send_message", "sendmessage", "send_invite",
                                     "reply_email", "forward_email")),
    ("a2a",               Tier.RED, ("delegate", "handoff", "spawn_agent", "call_agent",
                                     "subagent", "sub_agent", "dispatch_agent", "a2a")),
    ("skill_plugin",      Tier.RED, ("install", "load_skill", "load_plugin", "add_skill",
                                     "register_tool", "import_skill", "pip_install",
                                     "npm_install", "load_extension")),
    ("mcp_tool_call",     Tier.RED, ("mcp", "call_tool", "invoke_tool")),
    # --- LOW-tier (read / observe) ---
    ("filesystem_read",   Tier.LOW, ("read_file", "readfile", "cat", "open_file", "list_dir",
                                     "listdir", "ls", "stat", "load_file", "get_file",
                                     "head_file", "tail_file")),
    ("rag_vector_store",  Tier.LOW, ("retrieve", "vector_search", "query_docs", "fetch_kb",
                                     "similarity", "embed_search", "rag", "semantic_search",
                                     "knowledge_base")),
    ("web_content",       Tier.LOW, ("search", "browse", "fetch_page", "extract_content",
                                     "scrape", "read_url", "web_search", "get_page", "crawl")),
    ("email_calendar",    Tier.LOW, ("read_email", "list_email", "read_inbox", "list_events",
                                     "get_calendar", "read_mail", "fetch_email", "list_messages")),
]

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_ACRONYM = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")   # FHIRGet -> FHIR Get
_SPLIT = re.compile(r"[^a-z0-9]+")
_ALNUM = re.compile(r"[^a-z0-9]+")


def _camel_split(s: str) -> str:
    """Insert spaces at camelCase AND acronym→Word boundaries before lowercasing."""
    return _ACRONYM.sub(" ", _CAMEL.sub(" ", s)).lower()


def _token_list(name: str) -> list[str]:
    """Ordered lowercase tokens of a tool name (camelCase + acronym + separator split)."""
    return [t for t in _SPLIT.split(_camel_split(name)) if t]


def _norm(s: str) -> str:
    return _ALNUM.sub("", s.lower())


def _matches(keys: tuple[str, ...], toklist: list[str]) -> Optional[str]:
    """A single-word keyword must EQUAL a whole token; a multi-word keyword must
    appear as a CONTIGUOUS run of tokens. No substring matching — so "stat" can
    never match the token "state", and "load_file" can never match "DownloadFiles"."""
    tokset = set(toklist)
    for k in keys:
        parts = [p for p in _SPLIT.split(_camel_split(k)) if p]
        if not parts:
            continue
        if len(parts) == 1:
            if parts[0] in tokset:
                return k
        else:
            n = len(parts)
            for i in range(len(toklist) - n + 1):
                if toklist[i:i + n] == parts:
                    return k
    return None


# B2: reading sensitive personal / financial / health / location data is the steal
# half of an exfiltration. From an untrusted origin this is a RED secret-read even
# when no send is in the same call. (Trusted-origin reads still pass — Layer 2 only
# blocks untrusted→RED.) Generalized data categories, NOT benchmark tool names.
_READ_VERBS = ("read", "get", "view", "fetch", "download", "access", "list",
               "search", "retrieve", "export", "obtain", "lookup")
_SENSITIVE_HINTS = (
    "genetic", "dna", "patient", "prescription", "medical", "healthrecord", "health",
    "holdings", "portfolio", "savedaddress", "savedpayment", "paymentmethod",
    "creditcard", "bankaccount", "ssn", "passport", "searchhistory", "browsinghistory",
    "location", "geolocation", "personalinfo", "accountinformation", "linkedaccount",
    "userinfo", "userprofile", "publicrecord", "phonenumber", "biometric",
)


def classify_action(name: str, args: str = "") -> Optional[tuple[str, Tier, str]]:
    """Map a tool/function name (+ optional argument text) to (sink_surface, tier,
    reason). Returns None when the name matches no known capability (caller treats
    an unknown action as uncertain, not safe). Resource-aware promotions/demotions:
    secret/sensitive-data read -> RED identity_secrets; read-only DB query -> LOW.
    """
    if not name:
        return None
    toklist = _token_list(name)
    tokset = set(toklist)
    blob = (name + " " + (args or "")).lower()
    nblob = _norm(blob)

    def _sensitive_read():
        """True if this looks like a read of sensitive personal/financial/health data."""
        if not any(v in tokset for v in _READ_VERBS):
            return False
        return any(h in nblob for h in _SENSITIVE_HINTS)

    for surface, tier, keys in _ACTION_RULES:
        hit = _matches(keys, toklist)
        if hit:
            reason = f"{name!r} -> {surface} ({tier.value})"

            # resource-aware refinements -----------------------------------
            if surface in ("filesystem_read", "rag_vector_store", "web_content"):
                if any(h in blob for h in _SECRET_HINTS):
                    return ("identity_secrets", Tier.RED,
                            f"{name!r} reads secret-like target -> identity_secrets (RED)")
                if _sensitive_read():
                    return ("identity_secrets", Tier.RED,
                            f"{name!r} reads sensitive personal data -> identity_secrets (RED)")
            if surface == "database" and tier is Tier.RED:
                mutating = ("insert", "update", "delete", "drop", "alter", "truncate",
                            "create", "grant", "merge", "replace", "upsert")
                reads = ("select", "read", "get", "find", "fetch", "list")
                if not any(m in blob for m in mutating) and any(rd in blob for rd in reads):
                    return ("database", Tier.LOW, f"{name!r} read-only query -> database (LOW)")
            return (surface, tier, reason)

    # No keyword matched: still catch a sensitive-data read (steal half) that uses a
    # tool name we don't otherwise recognize.
    if _sensitive_read():
        return ("identity_secrets", Tier.RED,
                f"{name!r} reads sensitive personal data -> identity_secrets (RED)")
    return None


def labels_for(surface: str) -> dict:
    """OWASP-LLM / OWASP-Agentic / CWE labels for a surface (empty dict if unknown)."""
    s = SURFACE.get(surface)
    if not s:
        return {"owasp_llm": [], "owasp_agentic": [], "cwe": []}
    return {
        "owasp_llm": list(s["owasp_llm"]),
        "owasp_agentic": list(s["owasp_agentic"]),
        "cwe": list(s["cwe"]),
    }
