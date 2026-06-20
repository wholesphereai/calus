"""calus: prompt_injection  (4 patterns)"""

PATTERNS = [
    ('(?i)(?:readme|issue|comment).*git_init', 'critical', 'prompt-injection-git-attack: Content that appears designed to trick an LLM into misusing\nMCP git tools via prompt injection. Attackers embed'),
    ('(?i)(?:readme|issue|comment).*create.*repo.*/', 'critical', 'prompt-injection-git-attack: Content that appears designed to trick an LLM into misusing\nMCP git tools via prompt injection. Attackers embed'),
    ('(?i)please.*(?:init|create).*git.*(?:/etc|/root|~|\\.ssh)', 'critical', 'prompt-injection-git-attack: Content that appears designed to trick an LLM into misusing\nMCP git tools via prompt injection. Attackers embed'),
    ('(?i)helpful.*instruction.*git_init', 'critical', 'prompt-injection-git-attack: Content that appears designed to trick an LLM into misusing\nMCP git tools via prompt injection. Attackers embed'),
]