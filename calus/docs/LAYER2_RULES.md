# Calus — Layer 2 (Capability-Flow Graph) — Complete Rule Reference

> **Auto-generated** from `calus/taxonomy/taxonomy.py` + `calus/layers/layer2_flowgraph.py` by `calus/docs/_gen_layer2_rules.py`. Do not hand-edit; regenerate after any taxonomy change. This is the exhaustive contents of Layer 2 — nothing summarized away.

- Total surfaces: **16**
- Source nodes: **10** (trusted **1**, untrusted **9**)
- Sink nodes: **14** (RED **11**, LOW **3**)
- Forbidden edges (untrusted-source × RED-sink): **99**

## 1. Source nodes (taint origin)

A *source* is a surface that delivers content INTO the agent. Taint = whether the content can be attacker-influenced.

| Surface | Taint | Description |
|---|---|---|
| `direct_prompt` | **TRUSTED** | user instructions (the principal) |
| `mcp_tool_call` | **UNTRUSTED** | external tool invocation via MCP (poisoned descriptions/responses) |
| `tool_response` | **UNTRUSTED** | data returned by a called tool (indirect injection) |
| `rag_vector_store` | **UNTRUSTED** | retrieved documents (poisoned retrieval / embedding injection) |
| `web_content` | **UNTRUSTED** | browsed page content (indirect injection / hidden instructions) |
| `filesystem_read` | **UNTRUSTED** | read local files (path traversal, secret-read promotes to RED) |
| `email_calendar` | **UNTRUSTED** | incoming mail/invite (injection); send mail = RED external send |
| `memory_state` | **UNTRUSTED** | persistent memory (poisoning); write = RED (persists across turns) |
| `a2a` | **UNTRUSTED** | agent-to-agent (session smuggling); delegation = RED (rogue agent) |
| `skill_plugin` | **UNTRUSTED** | load skills/plugins (malicious skill, typosquat, supply chain) |

**Trusted sources (1):** `direct_prompt`

**Untrusted sources (9):** `mcp_tool_call`, `tool_response`, `rag_vector_store`, `web_content`, `filesystem_read`, `email_calendar`, `memory_state`, `a2a`, `skill_plugin`

## 2. Sink nodes (capabilities, tiered) with OWASP / CWE

A *sink* is a capability the agent can act through. **RED** = irreversible / external / costly (HIGH consequence). **LOW** = read-only / observe.

| Surface | Tier | Impact | OWASP-LLM | OWASP-Agentic | CWE | Description |
|---|---|---|---|---|---|---|
| `mcp_tool_call` | **RED** | high_consequence | LLM01 | ASI04, ASI07 | CWE-94, CWE-829 | external tool invocation via MCP (poisoned descriptions/responses) |
| `filesystem_write` | **RED** | high_consequence | LLM06 | ASI07 | CWE-73, CWE-552 | write/modify/delete files (configs, payloads, destructive delete) |
| `os_command_exec` | **RED** | high_consequence | LLM06 | ASI06, ASI07 | CWE-78, CWE-94 | run commands on host (RCE, command injection, rm -rf) |
| `database` | **RED** | high_consequence | LLM06, LLM08 | ASI07 | CWE-89, CWE-200 | query/write DB (SQLi, mass read, unauthorized write/delete) |
| `network_http` | **RED** | high_consequence | LLM06 | ASI07 | CWE-918 | outbound requests (SSRF, exfiltration, internal endpoints) |
| `identity_secrets` | **RED** | high_consequence | LLM02, LLM06 | ASI03 | CWE-522, CWE-798 | API keys / tokens / OAuth (credential leak, secret exfiltration) |
| `email_calendar` | **RED** | high_consequence | LLM01, LLM06 | ASI01, ASI07 | CWE-20 | incoming mail/invite (injection); send mail = RED external send |
| `payments_commerce` | **RED** | high_consequence | LLM06 | ASI06 | CWE-840 | spend money / place orders (unauthorized spend, overspend) |
| `memory_state` | **RED** | high_consequence | LLM01 | ASI02 | CWE-20 | persistent memory (poisoning); write = RED (persists across turns) |
| `a2a` | **RED** | high_consequence | LLM01 | ASI05 | CWE-94 | agent-to-agent (session smuggling); delegation = RED (rogue agent) |
| `skill_plugin` | **RED** | high_consequence | LLM03 | ASI04 | CWE-829 | load skills/plugins (malicious skill, typosquat, supply chain) |
| `rag_vector_store` | **LOW** | observe | LLM01, LLM08 | ASI01 | CWE-20 | retrieved documents (poisoned retrieval / embedding injection) |
| `web_content` | **LOW** | observe | LLM01 | ASI01 | CWE-79 | browsed page content (indirect injection / hidden instructions) |
| `filesystem_read` | **LOW** | observe | LLM02, LLM06 | ASI03 | CWE-22, CWE-200 | read local files (path traversal, secret-read promotes to RED) |

**RED sinks (11):** `mcp_tool_call`, `filesystem_write`, `os_command_exec`, `database`, `network_http`, `identity_secrets`, `email_calendar`, `payments_commerce`, `memory_state`, `a2a`, `skill_plugin`

**LOW sinks (3):** `rag_vector_store`, `web_content`, `filesystem_read`

## 3. Surface roles & coverage

Each surface can be a source, a sink, or both.

| Surface | Source? | Sink? | Role |
|---|---|---|---|
| `direct_prompt` | yes | no | source-only |
| `mcp_tool_call` | yes | RED | source+sink |
| `tool_response` | yes | no | source-only |
| `rag_vector_store` | yes | LOW | source+sink |
| `web_content` | yes | LOW | source+sink |
| `filesystem_read` | yes | LOW | source+sink |
| `filesystem_write` | no | RED | sink-only |
| `os_command_exec` | no | RED | sink-only |
| `database` | no | RED | sink-only |
| `network_http` | no | RED | sink-only |
| `identity_secrets` | no | RED | sink-only |
| `email_calendar` | yes | RED | source+sink |
| `payments_commerce` | no | RED | sink-only |
| `memory_state` | yes | RED | source+sink |
| `a2a` | yes | RED | source+sink |
| `skill_plugin` | yes | RED | source+sink |

**All 16 taxonomy surfaces are represented as nodes.** Modeled: 16. Unmodeled: 0 (none).

Notes on partial modeling (by design, not gaps in the flow rule):
- `tool_response` is a pure source (untrusted delivery channel); the actual capability it carries is whatever tool produced it, classified at the sink.
- `direct_prompt` is a pure source and the ONLY trusted one.
- `web_content`, `rag_vector_store`, `filesystem_read` are untrusted sources AND LOW-tier sinks; reads are permitted, but a secret-looking read promotes to the RED `identity_secrets` sink (see §6).

## 4. Forbidden-edge matrix (untrusted-source × RED-sink)

Rule: an untrusted-origin → RED-tier sink edge is **forbidden** unless the flow passed an explicit sanitize/allow node. `X` = forbidden (blocked).

| source \\ RED-sink | mcp_tool_c | filesystem | os_command | database | network_ht | identity_s | email_cale | payments_c | memory_sta | a2a | skill_plug |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `mcp_tool_call` | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** |
| `tool_response` | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** |
| `rag_vector_store` | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** |
| `web_content` | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** |
| `filesystem_read` | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** |
| `email_calendar` | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** |
| `memory_state` | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** |
| `a2a` | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** |
| `skill_plugin` | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** | **X** |

## 5. Complete forbidden-edge list (99 edges)

Every edge, enumerated, grouped by untrusted source.

**`mcp_tool_call` →** (untrusted)  
   1. `mcp_tool_call` → `mcp_tool_call` — RED — CWE-94, CWE-829 / ASI04, ASI07
   2. `mcp_tool_call` → `filesystem_write` — RED — CWE-73, CWE-552 / ASI07
   3. `mcp_tool_call` → `os_command_exec` — RED — CWE-78, CWE-94 / ASI06, ASI07
   4. `mcp_tool_call` → `database` — RED — CWE-89, CWE-200 / ASI07
   5. `mcp_tool_call` → `network_http` — RED — CWE-918 / ASI07
   6. `mcp_tool_call` → `identity_secrets` — RED — CWE-522, CWE-798 / ASI03
   7. `mcp_tool_call` → `email_calendar` — RED — CWE-20 / ASI01, ASI07
   8. `mcp_tool_call` → `payments_commerce` — RED — CWE-840 / ASI06
   9. `mcp_tool_call` → `memory_state` — RED — CWE-20 / ASI02
  10. `mcp_tool_call` → `a2a` — RED — CWE-94 / ASI05
  11. `mcp_tool_call` → `skill_plugin` — RED — CWE-829 / ASI04

**`tool_response` →** (untrusted)  
  12. `tool_response` → `mcp_tool_call` — RED — CWE-94, CWE-829 / ASI04, ASI07
  13. `tool_response` → `filesystem_write` — RED — CWE-73, CWE-552 / ASI07
  14. `tool_response` → `os_command_exec` — RED — CWE-78, CWE-94 / ASI06, ASI07
  15. `tool_response` → `database` — RED — CWE-89, CWE-200 / ASI07
  16. `tool_response` → `network_http` — RED — CWE-918 / ASI07
  17. `tool_response` → `identity_secrets` — RED — CWE-522, CWE-798 / ASI03
  18. `tool_response` → `email_calendar` — RED — CWE-20 / ASI01, ASI07
  19. `tool_response` → `payments_commerce` — RED — CWE-840 / ASI06
  20. `tool_response` → `memory_state` — RED — CWE-20 / ASI02
  21. `tool_response` → `a2a` — RED — CWE-94 / ASI05
  22. `tool_response` → `skill_plugin` — RED — CWE-829 / ASI04

**`rag_vector_store` →** (untrusted)  
  23. `rag_vector_store` → `mcp_tool_call` — RED — CWE-94, CWE-829 / ASI04, ASI07
  24. `rag_vector_store` → `filesystem_write` — RED — CWE-73, CWE-552 / ASI07
  25. `rag_vector_store` → `os_command_exec` — RED — CWE-78, CWE-94 / ASI06, ASI07
  26. `rag_vector_store` → `database` — RED — CWE-89, CWE-200 / ASI07
  27. `rag_vector_store` → `network_http` — RED — CWE-918 / ASI07
  28. `rag_vector_store` → `identity_secrets` — RED — CWE-522, CWE-798 / ASI03
  29. `rag_vector_store` → `email_calendar` — RED — CWE-20 / ASI01, ASI07
  30. `rag_vector_store` → `payments_commerce` — RED — CWE-840 / ASI06
  31. `rag_vector_store` → `memory_state` — RED — CWE-20 / ASI02
  32. `rag_vector_store` → `a2a` — RED — CWE-94 / ASI05
  33. `rag_vector_store` → `skill_plugin` — RED — CWE-829 / ASI04

**`web_content` →** (untrusted)  
  34. `web_content` → `mcp_tool_call` — RED — CWE-94, CWE-829 / ASI04, ASI07
  35. `web_content` → `filesystem_write` — RED — CWE-73, CWE-552 / ASI07
  36. `web_content` → `os_command_exec` — RED — CWE-78, CWE-94 / ASI06, ASI07
  37. `web_content` → `database` — RED — CWE-89, CWE-200 / ASI07
  38. `web_content` → `network_http` — RED — CWE-918 / ASI07
  39. `web_content` → `identity_secrets` — RED — CWE-522, CWE-798 / ASI03
  40. `web_content` → `email_calendar` — RED — CWE-20 / ASI01, ASI07
  41. `web_content` → `payments_commerce` — RED — CWE-840 / ASI06
  42. `web_content` → `memory_state` — RED — CWE-20 / ASI02
  43. `web_content` → `a2a` — RED — CWE-94 / ASI05
  44. `web_content` → `skill_plugin` — RED — CWE-829 / ASI04

**`filesystem_read` →** (untrusted)  
  45. `filesystem_read` → `mcp_tool_call` — RED — CWE-94, CWE-829 / ASI04, ASI07
  46. `filesystem_read` → `filesystem_write` — RED — CWE-73, CWE-552 / ASI07
  47. `filesystem_read` → `os_command_exec` — RED — CWE-78, CWE-94 / ASI06, ASI07
  48. `filesystem_read` → `database` — RED — CWE-89, CWE-200 / ASI07
  49. `filesystem_read` → `network_http` — RED — CWE-918 / ASI07
  50. `filesystem_read` → `identity_secrets` — RED — CWE-522, CWE-798 / ASI03
  51. `filesystem_read` → `email_calendar` — RED — CWE-20 / ASI01, ASI07
  52. `filesystem_read` → `payments_commerce` — RED — CWE-840 / ASI06
  53. `filesystem_read` → `memory_state` — RED — CWE-20 / ASI02
  54. `filesystem_read` → `a2a` — RED — CWE-94 / ASI05
  55. `filesystem_read` → `skill_plugin` — RED — CWE-829 / ASI04

**`email_calendar` →** (untrusted)  
  56. `email_calendar` → `mcp_tool_call` — RED — CWE-94, CWE-829 / ASI04, ASI07
  57. `email_calendar` → `filesystem_write` — RED — CWE-73, CWE-552 / ASI07
  58. `email_calendar` → `os_command_exec` — RED — CWE-78, CWE-94 / ASI06, ASI07
  59. `email_calendar` → `database` — RED — CWE-89, CWE-200 / ASI07
  60. `email_calendar` → `network_http` — RED — CWE-918 / ASI07
  61. `email_calendar` → `identity_secrets` — RED — CWE-522, CWE-798 / ASI03
  62. `email_calendar` → `email_calendar` — RED — CWE-20 / ASI01, ASI07
  63. `email_calendar` → `payments_commerce` — RED — CWE-840 / ASI06
  64. `email_calendar` → `memory_state` — RED — CWE-20 / ASI02
  65. `email_calendar` → `a2a` — RED — CWE-94 / ASI05
  66. `email_calendar` → `skill_plugin` — RED — CWE-829 / ASI04

**`memory_state` →** (untrusted)  
  67. `memory_state` → `mcp_tool_call` — RED — CWE-94, CWE-829 / ASI04, ASI07
  68. `memory_state` → `filesystem_write` — RED — CWE-73, CWE-552 / ASI07
  69. `memory_state` → `os_command_exec` — RED — CWE-78, CWE-94 / ASI06, ASI07
  70. `memory_state` → `database` — RED — CWE-89, CWE-200 / ASI07
  71. `memory_state` → `network_http` — RED — CWE-918 / ASI07
  72. `memory_state` → `identity_secrets` — RED — CWE-522, CWE-798 / ASI03
  73. `memory_state` → `email_calendar` — RED — CWE-20 / ASI01, ASI07
  74. `memory_state` → `payments_commerce` — RED — CWE-840 / ASI06
  75. `memory_state` → `memory_state` — RED — CWE-20 / ASI02
  76. `memory_state` → `a2a` — RED — CWE-94 / ASI05
  77. `memory_state` → `skill_plugin` — RED — CWE-829 / ASI04

**`a2a` →** (untrusted)  
  78. `a2a` → `mcp_tool_call` — RED — CWE-94, CWE-829 / ASI04, ASI07
  79. `a2a` → `filesystem_write` — RED — CWE-73, CWE-552 / ASI07
  80. `a2a` → `os_command_exec` — RED — CWE-78, CWE-94 / ASI06, ASI07
  81. `a2a` → `database` — RED — CWE-89, CWE-200 / ASI07
  82. `a2a` → `network_http` — RED — CWE-918 / ASI07
  83. `a2a` → `identity_secrets` — RED — CWE-522, CWE-798 / ASI03
  84. `a2a` → `email_calendar` — RED — CWE-20 / ASI01, ASI07
  85. `a2a` → `payments_commerce` — RED — CWE-840 / ASI06
  86. `a2a` → `memory_state` — RED — CWE-20 / ASI02
  87. `a2a` → `a2a` — RED — CWE-94 / ASI05
  88. `a2a` → `skill_plugin` — RED — CWE-829 / ASI04

**`skill_plugin` →** (untrusted)  
  89. `skill_plugin` → `mcp_tool_call` — RED — CWE-94, CWE-829 / ASI04, ASI07
  90. `skill_plugin` → `filesystem_write` — RED — CWE-73, CWE-552 / ASI07
  91. `skill_plugin` → `os_command_exec` — RED — CWE-78, CWE-94 / ASI06, ASI07
  92. `skill_plugin` → `database` — RED — CWE-89, CWE-200 / ASI07
  93. `skill_plugin` → `network_http` — RED — CWE-918 / ASI07
  94. `skill_plugin` → `identity_secrets` — RED — CWE-522, CWE-798 / ASI03
  95. `skill_plugin` → `email_calendar` — RED — CWE-20 / ASI01, ASI07
  96. `skill_plugin` → `payments_commerce` — RED — CWE-840 / ASI06
  97. `skill_plugin` → `memory_state` — RED — CWE-20 / ASI02
  98. `skill_plugin` → `a2a` — RED — CWE-94 / ASI05
  99. `skill_plugin` → `skill_plugin` — RED — CWE-829 / ASI04

## 6. Taint propagation & fail-safe default

- **Taint levels:** `trusted` / `untrusted` / `sanitized`.
- **`is_trusted(origin)`** → True only if the surface is *explicitly* `Taint.TRUSTED` in the taxonomy (currently ONLY `direct_prompt`).
- **FAIL-SAFE:** any origin that is not explicitly trusted — known-untrusted, unknown, mistyped, or empty — is treated as **UNTRUSTED**. An unrecognized origin can never bypass the forbidden-edge check by being mistaken for the user prompt.
- **`is_forbidden(origin, sink, sanitized)`** = `not is_trusted(origin)` and `sink is RED` and `not sanitized`.
- **Sanitize/allow node:** `sanitized=True` clears the edge (the only way an untrusted→RED flow is permitted).
- **`AgentContext` default origin** = `"unknown"` (untrusted).
- **Proxy `_origin_of()` assignment order:** (1) `x-calus-origin` / `x-calus-surface` header; (2) newest message role — `tool`/`function` → `tool_response` (untrusted), `user` → `direct_prompt` (trusted); (3) fail-safe fallback → `unknown` (untrusted).
- **Known integration caveat:** content stuffed into a `user`-role message without a label is seen as trusted; apps must keep external content in `tool`/`system` turns or set `x-calus-origin`.

## 7. Resource-aware promotions / demotions

The action classifier (`classify_action`) maps a tool name (+args) to a sink and refines the tier by the resource touched:

- **Secret-path read → RED `identity_secrets`:** a `filesystem_read` / `rag_vector_store` / `web_content` action whose name or args contain a secret-looking token is promoted from LOW to RED.
  - Secret hint tokens: `.env`, `id_rsa`, `id_ed25519`, `authorized_keys`, `.ssh`, `credentials`, `secret`, `secrets`, `api_key`, `apikey`, `api-key`, `token`, `password`, `passwd`, `shadow`, `.aws`, `.npmrc`, `.pypirc`, `mcp.json`, `.git-credentials`, `private_key`, `privatekey`, `keystore`, `.pem`
- **Sensitive-data read → RED `identity_secrets`:** a read verb (`read`/`get`/`view`/`fetch`/`download`/`access`/`list`/`search`/`retrieve`/`export`/`obtain`/`lookup`) together with a sensitive-data noun (genetic, dna, patient, prescription, medical, health, holdings, portfolio, saved-address, payment-method, credit-card, bank-account, ssn, passport, search/browsing history, location, personal-info, account-information, linked-account, user-info/profile, public-record, phone-number, biometric) is promoted from a LOW read to RED — this catches the *steal half* of an exfiltration even with no send in the same call. (Trusted-origin reads still pass; Layer 2 only blocks untrusted→RED.) Generalized data categories, NOT benchmark tool names.
- **Read-only DB query → LOW `database`:** a `database` action with a read verb and NO mutating verb (`insert`/`update`/`delete`/`drop`/`alter`/`truncate`/`create`/`grant`/`merge`/`replace`/`upsert`) is demoted RED→LOW.
- **Unknown tool → `None`:** a tool name matching no rule is NOT classified (the decision-maker treats a pending unknown action as uncertain, not safe).

## 8. Action classifier — full keyword → sink map

Token-aware matching (NOT substring): a **single-word** keyword must EQUAL a whole token of the tool name (tokens come from camelCase + acronym + separator splitting, so `stat` never matches the token `state`); a **multi-word** keyword must appear as a **contiguous run** of tokens. Rules evaluated top-to-bottom (most dangerous first); first match wins.

| # | Sink | Tier | Match keywords |
|---|---|---|---|
| 1 | `os_command_exec` | RED | `exec`, `execute`, `shell`, `bash`, `sh`, `cmd`, `run`, `command`, `run_code`, `runcode`, `subprocess`, `spawn`, `eval`, `interpreter`, `powershell`, `terminal`, `popen`, `unlock`, `grant_access`, `guest_access`, `actuate`, `dispatch` |
| 2 | `payments_commerce` | RED | `pay`, `payment`, `payout`, `charge`, `checkout`, `purchase`, `order`, `refund`, `invoice`, `billing`, `stripe`, `transaction`, `wire`, `transfer`, `withdraw`, `deposit`, `trade` |
| 3 | `identity_secrets` | RED | `secret`, `credential`, `vault`, `get_token`, `read_key`, `api_key`, `apikey`, `oauth`, `keychain`, `keystore`, `private_key`, `secrets`, `two_factor`, `2fa`, `auto_fill`, `share_password`, `sharepassword`, `share_data`, `deepfake` |
| 4 | `network_http` | RED | `http`, `https`, `url`, `curl`, `webhook`, `upload`, `egress`, `ssrf`, `exfil`, `outbound`, `post_request`, `send_request` |
| 5 | `memory_state` | RED | `write_memory`, `save_memory`, `store_memory`, `set_memory`, `update_memory`, `remember`, `memorize`, `persist` |
| 6 | `filesystem_write` | RED | `write_file`, `writefile`, `write`, `delete_file`, `deletefile`, `modify_file`, `save_file`, `put_file`, `edit_file`, `append_file`, `overwrite`, `unlink`, `rmdir`, `mkdir`, `rm` |
| 7 | `database` | RED | `sql`, `db`, `insert`, `update`, `delete`, `drop`, `truncate`, `alter`, `upsert`, `grant`, `mysql`, `psql`, `postgres`, `mongo`, `redis`, `sqlite`, `execute_query` |
| 8 | `email_calendar` | RED | `send_email`, `sendmail`, `send_mail`, `smtp`, `send`, `send_message`, `sendmessage`, `send_invite`, `reply_email`, `forward_email` |
| 9 | `a2a` | RED | `delegate`, `handoff`, `spawn_agent`, `call_agent`, `subagent`, `sub_agent`, `dispatch_agent`, `a2a` |
| 10 | `skill_plugin` | RED | `install`, `load_skill`, `load_plugin`, `add_skill`, `register_tool`, `import_skill`, `pip_install`, `npm_install`, `load_extension` |
| 11 | `mcp_tool_call` | RED | `mcp`, `call_tool`, `invoke_tool` |
| 12 | `filesystem_read` | LOW | `read_file`, `readfile`, `cat`, `open_file`, `list_dir`, `listdir`, `ls`, `stat`, `load_file`, `get_file`, `head_file`, `tail_file` |
| 13 | `rag_vector_store` | LOW | `retrieve`, `vector_search`, `query_docs`, `fetch_kb`, `similarity`, `embed_search`, `rag`, `semantic_search`, `knowledge_base` |
| 14 | `web_content` | LOW | `search`, `browse`, `fetch_page`, `extract_content`, `scrape`, `read_url`, `web_search`, `get_page`, `crawl` |
| 15 | `email_calendar` | LOW | `read_email`, `list_email`, `read_inbox`, `list_events`, `get_calendar`, `read_mail`, `fetch_email`, `list_messages` |

## 9. What Layer 2 does NOT cover (current gaps)

- **Attack *content* detection** (jailbreak/injection wording) is Layer 1's job, not Layer 2's. Layer 2 is purely structural (taint × capability).
- **Semantic / novel-attack judgment** is the Layer 3 model — a hook only, not built. Until benchmark results identify proven misses, no speculative edges/sinks are added (see Task 2).
- **RAG-stuffing inside a user turn** (see §6 caveat) — an integration requirement, not something Layer 2 can infer.
- **Gap-driven additions pending:** new rules/edges/sinks will be added ONLY for attack types a benchmark proves are missed, each annotated with the specific miss it addresses.
