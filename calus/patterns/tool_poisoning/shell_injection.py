"""tool-poisoning: shell-injection  (1 patterns)"""

PATTERNS = [
    ('(?:(?:;|then)\\s+(?:curl|wget|nc|bash|sh|python3?|powershell|cmd(?:\\.exe)?)\\s+(?:-|\\w|http|https|\'|"|\\$)|\\&\\&\\s+(?:curl|wget)\\s+[^\\n]*\\$\\(|\\&\\&\\s+(?:bash|sh)\\s+-[cs]\\s+|\\&\\&\\s+(?:python3?)\\s+-[ce]\\s+(?:\'|"|import|os\\.|urllib|subprocess)|\\|\\s+(?:nc)\\s+\\S+\\s+\\d+|\\|\\s+(?:bash|sh)\\s+-[cs]\\s+|\\|\\s+(?:python3?)\\s+-[ce]\\s+(?:import|os\\.|urllib|subprocess|open\\(|requests|socket))', 'critical', "Structural shell injection pattern using multiple conditions: (A) Semicolon or 'then' chaining to curl/wget/nc/bash/sh/python/powershell/cmd"),
]