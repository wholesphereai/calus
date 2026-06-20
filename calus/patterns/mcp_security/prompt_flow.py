"""calus: prompt-flow  (20 patterns)"""

PATTERNS = [
    ('(?i)\\bpfi_enabled\\s*=\\s*False', 'low', 'prompt-flow-integrity-bypass: Detects code that disables Prompt Flow Integrity (PFI) checks, allowing untrusted data to escalate privileges.'),
    ('(?i)\\bdisable_pfi\\s*=', 'low', 'prompt-flow-integrity-bypass: Detects code that disables Prompt Flow Integrity (PFI) checks, allowing untrusted data to escalate privileges.'),
    ('(?i)#\\s*pfi\\s*(?:bypass|disabled)', 'low', 'prompt-flow-integrity-bypass: Detects code that disables Prompt Flow Integrity (PFI) checks, allowing untrusted data to escalate privileges.'),
    ('(?i)\\bpfi_enabled\\s*[:=]\\s*(?:False|0)\\b', 'low', 'mcp-prompt-flow-integrity-absence: Detects missing Prompt Flow Integrity (PFI) enforcement in MCP server configurations, allowing untrusted '),
    ('(?i)\\bprompt_flow_integrity\\s*[:=]\\s*(?:False|None|0)\\b', 'low', 'mcp-prompt-flow-integrity-absence: Detects missing Prompt Flow Integrity (PFI) enforcement in MCP server configurations, allowing untrusted '),
    ('(?i)\\btrace_untrusted\\s*[:=]\\s*(?:False|0)\\b', 'low', 'mcp-prompt-flow-integrity-absence: Detects missing Prompt Flow Integrity (PFI) enforcement in MCP server configurations, allowing untrusted '),
    ('(?i)\\bpfi\\s*(?:enabled|active|check)\\s*[:=]\\s*(?:False|0|null|disabled|off)\\b', 'low', 'mcp-prompt-flow-integrity-disabled: Detects disabled Prompt Flow Integrity (PFI) checks, enabling privilege escalation through untrusted dat'),
    ('(?i)\\bprompt_flow_integrity\\s*[:=]\\s*(?:False|0|null|disabled|off)\\b', 'low', 'mcp-prompt-flow-integrity-disabled: Detects disabled Prompt Flow Integrity (PFI) checks, enabling privilege escalation through untrusted dat'),
    ('(?i)\\b(?:disable|skip|bypass)_pfi\\b', 'low', 'mcp-prompt-flow-integrity-disabled: Detects disabled Prompt Flow Integrity (PFI) checks, enabling privilege escalation through untrusted dat'),
    ('(?i)(?:disable|skip|bypass)\\s*.{0,40}\\b(?:pfi|prompt.?flow.?integrity|flow.?check)\\b', 'low', 'mcp-prompt-flow-integrity-bypass: Detects code that bypasses Prompt Flow Integrity (PFI) enforcement, as described in AgenticCyOps §3.1.2. P'),
    ('(?i)\\b(?:pfi|prompt.?flow)\\s*.{0,40}\\b(?:false|disabled|off)\\b', 'low', 'mcp-prompt-flow-integrity-bypass: Detects code that bypasses Prompt Flow Integrity (PFI) enforcement, as described in AgenticCyOps §3.1.2. P'),
    ('(?i)(?:from|import)\\s+.{0,40}prompt.{0,40}flow.{0,40}integrity.{0,40}bypass', 'low', 'mcp-prompt-flow-integrity-bypass: Detection of PFI bypass attempts where untrusted data sources are not distinguished, enabling privilege es'),
    ('(?i)\\bPFI\\b.{0,40}\\b(?:bypass|disable|ignore)\\b', 'low', 'mcp-prompt-flow-integrity-bypass: Detection of PFI bypass attempts where untrusted data sources are not distinguished, enabling privilege es'),
    ('(?i)(?:def|class).{0,60}(?:validate_prompt_flow|check_prompt_integrity|pfi_check)', 'medium', 'mcp-prompt-flow-integrity-check-missing: Detects missing Prompt Flow Integrity (PFI) enforcement in agent code, which enables privilege esca'),
    ('(?i)from\\s+.{0,40}pfi\\s+import|import\\s+.{0,40}pfi\\b', 'medium', 'mcp-prompt-flow-integrity-check-missing: Detects missing Prompt Flow Integrity (PFI) enforcement in agent code, which enables privilege esca'),
    ('(?i)PFI\\.(?:disable|skip|bypass|ignore)\\s*\\(', 'low', 'mcp-prompt-flow-integrity-bypass: Detects disabling or bypassing of prompt flow integrity checks that track instruction provenance.'),
    ('(?i)prompt_flow_integrity\\s*=\\s*(?:False|None|0)', 'low', 'mcp-prompt-flow-integrity-bypass: Detects disabling or bypassing of prompt flow integrity checks that track instruction provenance.'),
    ('(?i)(?:untrusted|bypass)_flow\\s*[:=]\\s*(?:True|1|yes)', 'low', 'mcp-prompt-flow-integrity-bypass: Detects disabling or bypassing of prompt flow integrity checks that track instruction provenance.'),
    ('(?i)def\\s+check_flow_integrity|def\\s+enforce_boundary', 'low', 'mcp-prompt-flow-integrity: Detects Prompt Flow Integrity (PFI) mechanisms for enforcing instruction boundaries and least privilege.'),
    ('(?i)pfi_validator', 'low', 'mcp-prompt-flow-integrity: Detects Prompt Flow Integrity (PFI) mechanisms for enforcing instruction boundaries and least privilege.'),
]