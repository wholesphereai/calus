"""calus: session-isolation  (18 patterns)"""

PATTERNS = [
    ('(?i)shared_session\\s*[:=]\\s*(?:True|1|yes\\b)', 'low', 'mcp-session-isolation-missing: Detects MCP client configurations that omit session isolation, enabling cross-session contamination.'),
    ('(?i)session_isolation\\s*[:=]\\s*False', 'low', 'mcp-session-isolation-missing: Detects MCP client configurations that omit session isolation, enabling cross-session contamination.'),
    ('(?i)\\b(?:global|class\\s+[\\w]*Server)\\b[\\s\\S]{0,500}(?:dict\\s*=\\s*\\{|list\\s*=\\s*\\[)\\s*[^}]{0,100}\\b(?:tool|session|context)\\b', 'high', 'mcp-session-isolation-missing-shared-state: Detects MCP server code that uses global mutable state across sessions, enabling cross-session c'),
    ('(?i)\\b(?:session|user|context)_store\\s*=\\s*\\{\\}', 'high', 'mcp-session-isolation-missing-shared-state: Detects MCP server code that uses global mutable state across sessions, enabling cross-session c'),
    ('(?i)\\bSHARED\\s*=\\s*\\{', 'high', 'mcp-session-isolation-missing-shared-state: Detects MCP server code that uses global mutable state across sessions, enabling cross-session c'),
    ('(?i)(?:from|import)\\s+.{0,40}\\b(?:sharedstate|globalctx)\\b', 'low', 'mcp-session-isolation-violation-shared-state: Detects shared mutable state across MCP sessions (Cross-Session Contamination per Guo et al.).'),
    ('(?i)global\\s+session_data\\s*=\\s*\\{', 'low', 'mcp-session-isolation-bypass-code: Detects code that bypasses session isolation by sharing mutable state across MCP sessions.'),
    ('(?i)\\bshared\\s*=\\s*mcp\\.(?:Server|Client)\\(.{0,40}?\\).{0,40}?\\bpersist', 'low', 'mcp-session-isolation-bypass-code: Detects code that bypasses session isolation by sharing mutable state across MCP sessions.'),
    ('(?i)\\bclass\\s+SharedStateFactory\\b', 'low', 'mcp-session-isolation-bypass-code: Detects code that bypasses session isolation by sharing mutable state across MCP sessions.'),
    ('(?i)\\bsingleton\\s*=\\s*None', 'low', 'mcp-session-isolation-bypass-code: Detects code that bypasses session isolation by sharing mutable state across MCP sessions.'),
    ('(?i)(?:shared|global|common|static)\\s+\\w*\\s*(?:context|state|store|cache|registry)\\s*[=:]\\s*\\{\\s*(?:[\'"]\\w+[\'"]\\s*[=:])?', 'low', 'mcp-session-isolation-bypass-shared-context: Detects shared mutable context objects that can be used for cross-session contamination attacks'),
    ('(?i)(?:session|context)\\s*\\.\\s*(?:put|set|store|merge|update|append)\\s*\\(.{0,40}?[\'"]\\s*(?:shared|global|common|public)\\s*[\'"]', 'low', 'mcp-session-isolation-bypass-shared-context: Detects shared mutable context objects that can be used for cross-session contamination attacks'),
    ('(?i)\\b(?:context\\s+manager|shared_state|global_registry)\\s*\\(\\s*["\'\\[]?(?:\\w+)?', 'low', 'mcp-session-isolation-bypass-shared-context: Detects shared mutable context objects that can be used for cross-session contamination attacks'),
    ('(?i)(?:multiuser|multi\\s*user|shared\\s*state).{0,40}(?:mcp|tool|server).{0,40}(?:cache|store|pollut|contaminat)', 'low', 'mcp-session-isolation-bypass: Detects potential cross-session contamination by identifying shared state across MCP sessions.'),
    ('(?i)(?:from|import).{0,40}(?:shared_session|global_context|persistent_cache)', 'low', 'mcp-session-isolation-bypass: Detects potential cross-session contamination by identifying shared state across MCP sessions.'),
    ('(?i)(?:open|write|dump|save)\\s*\\(\\s*[\'"][^\'"]{0,100}\\.mcp_context', 'medium', 'mcp-session-isolation-bypass-persistent-context: Detects code that uses file-based shared context to persist malicious artifacts across sess'),
    ('(?i)shared_memory\\s*=\\s*(?:open|mmap|sharedctypes)', 'medium', 'mcp-session-isolation-bypass-persistent-context: Detects code that uses file-based shared context to persist malicious artifacts across sess'),
    ('(?i)(?:json|pickle|yaml)\\.(?:dump|dumps)\\s*\\(\\s*.{0,40}?\\s*,\\s*(?:open|file)\\s*\\(\\s*[\'"]', 'medium', 'mcp-session-isolation-bypass-persistent-context: Detects code that uses file-based shared context to persist malicious artifacts across sess'),
]