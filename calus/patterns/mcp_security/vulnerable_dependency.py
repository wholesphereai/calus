"""calus: vulnerable_dependency  (4 patterns)"""

PATTERNS = [
    ('(?i)mcp-server-git.*[\'"]\\s*[<:]\\s*[\'"]?2025\\.9\\.2[0-4]', 'critical', 'cve-2025-68143-vulnerable-version: mcp-server-git versions before 2025.9.25 are vulnerable to path traversal\nvia the git_init tool. This all'),
    ('(?i)mcp-server-git@[0-9]+\\.[0-9]+\\.[0-9]+', 'critical', 'cve-2025-68143-vulnerable-version: mcp-server-git versions before 2025.9.25 are vulnerable to path traversal\nvia the git_init tool. This all'),
    ('(?i)[\'"]mcp-server-git[\'"]\\s*:\\s*[\'"]\\^?[0-9]', 'critical', 'cve-2025-68143-vulnerable-version: mcp-server-git versions before 2025.9.25 are vulnerable to path traversal\nvia the git_init tool. This all'),
    ('(?i)pip\\s+install\\s+mcp-server-git(?!.*>=2025\\.9\\.25)', 'critical', 'cve-2025-68143-vulnerable-version: mcp-server-git versions before 2025.9.25 are vulnerable to path traversal\nvia the git_init tool. This all'),
]