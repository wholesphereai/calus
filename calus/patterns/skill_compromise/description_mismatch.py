"""skill-compromise: description-mismatch  (5 patterns)"""

PATTERNS = [
    ('(?i)(rm\\s+-rf|unlink|deleteFile|removeDir|fs\\.write|writeFile|appendFile|truncate)', 'medium', ''),
    ('(?i)(curl|wget|fetch|http\\.request|axios\\.|net\\.connect|socket\\.connect)', 'medium', ''),
    ('(?i)(child_process|spawn|exec|execFile|system\\(|popen|subprocess)', 'medium', ''),
    ('(?i)(process\\.env|os\\.environ|getenv|\\$\\{?[A-Z_]+\\}?|secrets?\\.|credentials?)', 'medium', ''),
    ('(?i)(password|api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key|bearer\\s+[a-zA-Z0-9])', 'medium', ''),
]