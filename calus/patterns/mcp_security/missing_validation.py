"""calus: missing_validation  (2 patterns)"""

PATTERNS = [
    ('handler\\s*:\\s*async\\s*\\([^)]*\\)\\s*=>\\s*\\{[^}]*(?!.*(?:parse|validate|sanitize))[^}]*input\\.', 'medium', 'handler-uses-input-without-apparent-validation: '),
    ('def\\s+\\w+\\s*\\([^)]*\\):[^:]*(?!.*(?:pydantic|validator))[^:]*input\\[', 'medium', 'function-uses-input-without-apparent-validation: '),
]