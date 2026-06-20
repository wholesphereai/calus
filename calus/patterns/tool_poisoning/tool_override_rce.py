"""tool-poisoning: tool-override-rce  (4 patterns)"""

PATTERNS = [
    ('(?i)tool[_-]?override[^\\n]{0,300}(?:os\\.system|subprocess\\.|exec\\s*\\(|eval\\s*\\(|__import__|importlib\\.import|open\\s*\\([^)]{0,80}["\\x27]w["\\x27])', 'critical', 'tool_override payload combined with Python code execution primitives (os.system, subprocess, exec, eval, __import__) — direct CVE-2026-44334'),
    ('(?i)tool[_-]?override[^\\n]{0,200}(?:&&|\\|\\||;|`|\\$\\()[^\\n]{0,100}(?:curl|wget|bash|sh|nc|ncat)', 'critical', 'tool_override with shell metacharacters followed by network/shell execution primitives — command injection via tool override\n'),
    ('(?i)(?:CVE-2026-44334|CVE-2026-40287[^\\n]{0,80}bypass|tool[_-]?override[^\\n]{0,80}(?:bypass|patch[_-]?bypass))[^\\n]{0,200}(?:inject|exec|exploit|rce|unauthenticated|unauth)', 'critical', 'Explicit CVE-2026-44334 / CVE-2026-40287 patch bypass reference combined with exploitation language — attack framing\n'),
    ('(?i)(?:praisonai|praison)[^\\n]{0,100}tool[_-]?override[^\\n]{0,200}(?:inject|exec|exploit|bypass|rce|command|shell)', 'critical', 'PraisonAI + tool_override combined with exploitation language — CVE-2026-44334 attack framing in skill or tool description\n'),
]