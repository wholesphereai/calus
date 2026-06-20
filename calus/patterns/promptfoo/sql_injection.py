"""
CALUS.patterns.promptfoo.sql_injection
Patterns inspired by Promptfoo redteam plugins — sql_injection.
"""
from calus.patterns.base import Pattern, register, HIGH

register(
    Pattern(text="'; DROP TABLE users; --", family="sql_injection", severity=HIGH, source="promptfoo", tags=["sql_injection"]),
    Pattern(text="1' OR '1'='1", family="sql_injection", severity=HIGH, source="promptfoo", tags=["sql_injection"]),
    Pattern(text="admin'--", family="sql_injection", severity=HIGH, source="promptfoo", tags=["sql_injection"]),
    Pattern(text="' UNION SELECT * FROM", family="sql_injection", severity=HIGH, source="promptfoo", tags=["sql_injection"]),
    Pattern(text="1; SELECT * FROM information_schema", family="sql_injection", severity=HIGH, source="promptfoo", tags=["sql_injection"]),
    Pattern(text="' OR 1=1--", family="sql_injection", severity=HIGH, source="promptfoo", tags=["sql_injection"]),
    Pattern(text="'; INSERT INTO users", family="sql_injection", severity=HIGH, source="promptfoo", tags=["sql_injection"]),
    Pattern(text="EXEC xp_cmdshell", family="sql_injection", severity=HIGH, source="promptfoo", tags=["sql_injection"]),
    Pattern(text="1' AND SLEEP(5)--", family="sql_injection", severity=HIGH, source="promptfoo", tags=["sql_injection"]),
)
