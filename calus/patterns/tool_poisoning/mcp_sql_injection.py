"""tool-poisoning: mcp-sql-injection  (3 patterns)"""

PATTERNS = [
    ('(?i)"(?:query|sql|statement|command)"\\s*:\\s*"[^"]{0,300}(?:\';\\s*(?:drop|delete|insert|update|create|alter|truncate)\\s+|\'\\s*(?:or|and)\\s*\'[^\']{0,50}\'\\s*=\\s*\'|union\\s+(?:all\\s+)?select|--\\s*$|/\\*[^*]{0,50}\\*/|xp_cmdshell|information_schema|pg_sleep|waitfor\\s+delay)[^"]{0,200}"', 'critical', 'SQL injection payload in MCP tool query argument — CVE-2025-66335 Apache Doris exploitation pattern'),
    ('(?i)"url"\\s*:\\s*"https?://[^"]{0,120}(?:apache[_\\-]?doris|doris[_\\-]?mcp|doris\\.apache)[^"]{0,60}(?:/mcp|/tools?|/api)[^"]*"(?![\\s\\S]{0,400}"(?:auth|headers?|token|apiKey|authorization|bearer)")', 'critical', 'MCP config pointing at Apache Doris endpoint without auth — unauthenticated SQL injection surface'),
    ('(?i)(?:apache[_\\-]?doris|doris[_\\-]?mcp)[^\\n]{0,200}(?:sql\\s+injection|unsaniti[sz]ed|inject[^\\n]{0,50}(?:query|sql)|cve[_\\-]?2025[_\\-]?66335|drop\\s+table|union\\s+select)', 'critical', 'Content describing or weaponising Apache Doris MCP SQL injection — CVE-2025-66335 framing'),
]