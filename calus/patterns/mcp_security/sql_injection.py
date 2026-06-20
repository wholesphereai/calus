"""calus: sql_injection  (7 patterns)"""

PATTERNS = [
    ('execute\\s*\\(\\s*f["\\\'].*\\{', 'critical', 'sql-with-f-string-interpolation: '),
    ('execute\\s*\\([^)]*%\\s*\\(', 'critical', 'sql-with--formatting: '),
    ('execute\\s*\\([^)]*\\.format\\s*\\(', 'critical', 'sql-with-format: '),
    ('execute\\s*\\([^)]*\\+\\s*["\\\']?\\s*\\+?\\s*(input|query|param|user|data)\\b', 'critical', 'sql-with-string-concatenation: '),
    ('(SELECT|INSERT|UPDATE|DELETE|DROP).*\\+\\s*["\\\']?\\s*\\+', 'critical', 'raw-sql-with-concatenation: '),
    ('query\\s*\\(\\s*["\\\'].*\\$\\{', 'critical', 'sql-query-with-template-literal: '),
    ('rawQuery\\s*\\([^)]*\\+', 'high', 'raw-query-with-concatenation: '),
]