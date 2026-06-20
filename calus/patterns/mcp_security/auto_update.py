"""calus: auto_update  (9 patterns)"""

PATTERNS = [
    ('auto[_-]?update\\s*[=:]\\s*["\\\']?(?:true|yes|enabled|1)["\\\']?', 'medium', 'mcp123-auto-update-enabled-without-integrity-check: '),
    ('self[_-]?update\\s*\\(', 'medium', 'mcp123-self-update-function-check-for-integrity-ve: '),
    ('fetch[_-]?latest[_-]?version\\s*\\(', 'medium', 'mcp123-fetches-latest-version-check-for-signature-: '),
    ('download\\s*\\([^)]*\\)(?!.*(?:checksum|hash|verify|signature))', 'high', 'mcp123-download-without-integrity-verification: '),
    ('update\\s*\\([^)]*\\)(?!.*(?:verify|sign|hash))', 'high', 'mcp123-update-without-verification: '),
    ('install\\s*\\([^)]*(?:url|http)[^)]*\\)(?!.*signature)', 'high', 'mcp123-install-from-url-without-signature-check: '),
    ('(?:eval|exec)\\s*\\(\\s*(?:await\\s+)?(?:fetch|request|axios)', 'critical', 'mcp123-dynamic-code-execution-from-remote-source: '),
    ('import\\s*\\([^)]*\\+[^)]*\\)', 'high', 'mcp123-dynamic-import-with-concatenation: '),
    ('require\\s*\\([^)]*\\+[^)]*\\)', 'high', 'mcp123-dynamic-require-with-concatenation: '),
]