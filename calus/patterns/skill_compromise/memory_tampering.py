"""skill-compromise: memory-tampering  (3 patterns)"""

PATTERNS = [
    ('(?:write|append|modify|edit|overwrite|replace|inject|insert)\\s+.{0,50}\\b(MEMORY|SOUL|CLAUDE)\\.md\\b', 'critical', 'Direct reference to writing/modifying an agent memory file'),
    ('(?:echo|cat|printf|tee)\\s+.{0,80}>\\s*\\S*\\b(MEMORY|SOUL|CLAUDE)\\.md\\b', 'critical', 'Shell redirect overwriting an agent memory file'),
    ('(?:echo|printf)\\s+.{0,80}>>\\s*\\S*\\b(MEMORY|SOUL|CLAUDE)\\.md\\b', 'critical', 'Shell append to an agent memory file'),
]