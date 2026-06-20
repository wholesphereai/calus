"""skill-compromise: skill-overreach  (5 patterns)"""

PATTERNS = [
    ('(?i)allowed[_-]tools:.*Bash\\s*\\(\\s*\\*\\s*\\)(?![:\\w])', 'high', 'Unrestricted Bash(*) access — excludes scoped Bash(git:*) etc. (OWASP AST03)'),
    ('(?i)(set|write|add|configure|enable)\\s+.{0,30}(autoApprove|auto[_-]approve|always[_-]approve).{0,10}(true|yes|on)|"chat\\.tools\\.autoApprove"\\s*:\\s*true', 'high', 'Setting auto-approve to true (CVE-2025-53773)'),
    ('(?i)(disable|turn\\s+off|deactivate)\\s+(the\\s+)?(agent|ai|skill|claude|copilot)\\s+(sandbox|safety|guardrail|restriction|permission)s?', 'high', 'Disabling AI agent safety mechanisms specifically'),
    ('(?i)(write|append|modify|update|overwrite)\\s+(?:to\\s+)?(?:(?<![\\w./])(?:SOUL\\.md|MEMORY\\.md|AGENTS\\.md)|\\.claude/settings|openclaw\\.json)', 'high', 'Write to agent identity/memory files (OWASP AST01 persistence) — bare SOUL.md/MEMORY.md/AGENTS.md only, excludes user-app paths like .archiv'),
    ('(?i)(read|access|scan|search)\\s+(all|every|any)\\s+(files?|directories|directory|paths?|folders?)\\s+(in|on|under|across)\\s+(the\\s+)?(system|machine|computer|home\\s+directory|entire|~/)', 'high', 'Wildcard filesystem access request — requires system/home/entire scope'),
]