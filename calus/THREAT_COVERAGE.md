# Calus — Threat Coverage

Mapped to the OWASP LLM Top 10 and common agent-threat frameworks. Calus is a
**detection engine** (text in → verdict out) plus a **redaction** helper.

| Area | Coverage | How |
|---|---|---|
| Prompt Injection | ✅ Strong | ~5,700 injection patterns + similarity + obfuscation decoders |
| Jailbreak / System Override | ✅ Strong | ~4,800 jailbreak patterns (DAN, dev-mode, restriction bypass) |
| Web Attacks (XSS/CSRF/SSRF/SSTI) | ✅ Added | `patterns/web_attacks` — script/event-handler XSS, CSRF auto-submit, SSRF to metadata, template-injection RCE gadgets |
| MCP Tool Poisoning | ✅ Added/Strong | ~3,300 MCP patterns + `patterns/mcp_tool_poisoning` (hidden tool-desc instructions, rug-pull, shadowing) + MCP guardrail provider |
| Malicious Code Execution | ✅ Added | `patterns/code_execution_ext` — destructive shell, eval/exec sinks, reverse shells, deserialization, download-and-exec |
| PII & Credential Exposure | ✅ Detect + Redact | `patterns/pii_credentials` to detect; `calus.redact()` to MASK (AWS/API keys, JWT, SSN, cards, IBAN, email, phone) |
| Confidential Data | 🟡 Detect | privacy/RAG patterns + canary tokens (detection; pair with `redact()` for masking) |
| Unauthorized Access / Priv-Esc | ✅ Added | `patterns/access_control` — privilege escalation, auth bypass, sudo/setuid, path traversal |
| Excessive Agency / Agent Abuse | ✅ Strong | behavioral layer (tool-call screening, memory poisoning) via `agent_context` |
| NSFW Content | ❌ Out of scope | Calus is a security detector, not a content-moderation classifier |
| Off-Topic Drift | ❌ Out of scope | No topic-adherence model |

## Redaction (enforcement helper)
```python
from calus import redact
out = redact("key sk-... SSN 123-45-6789 card 4111 1111 1111 1111")
out.text       # '... [API_KEY-1264] ... [SSN-1e87] ... [CREDIT_CARD-b436]'
out.findings   # [('API_KEY', ...), ('SSN', ...), ('CREDIT_CARD', ...)]
```

## Honest positioning
Calus is the open-source **detection layer** — strongest on prompt injection,
jailbreak, MCP poisoning, web/code-exec payloads, and credential detection. It
detects (and for PII, redacts); it is not a full network enforcement gateway.
Pair it with your own proxy/guardrail for blocking, logging, and policy.
