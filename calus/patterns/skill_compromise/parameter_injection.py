"""skill-compromise: parameter-injection  (5 patterns)"""

PATTERNS = [
    ('(?i)(;|&&|\\|\\||`|\\$\\()\\s*(cat|ls|id|whoami|uname|pwd|env|curl|wget|nc|bash|sh|python)', 'critical', ''),
    ('(?i)(\'\\s*(OR|AND|UNION)\\s+\'|\'?\\s*;\\s*(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE)\\s|--\\s*[;\\"\'\\)\\]]|/\\*.*\\*/)', 'critical', ''),
    ('(\\.\\./|\\.\\.\\\\){2,}|(\\.\\.(/|\\\\)){2,}(etc|windows|usr|home|root|var|tmp)', 'critical', ''),
    ('(?i)(\\{\\{.*\\}\\}|\\$\\{.*\\}|<%.*%>|#\\{.*\\}|\\{%.*%\\})', 'critical', ''),
    ('(?i)(\\x00|%00|\\\\0|null\\s*byte|\\\\u0000)', 'critical', ''),
]