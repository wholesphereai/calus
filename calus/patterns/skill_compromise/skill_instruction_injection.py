"""skill-compromise: skill-instruction-injection  (5 patterns)"""

PATTERNS = [
    ('(?i)(you\\s+are\\s+(now\\s+)?in\\s+(developer|unrestricted|god|admin|root)\\s+mode|security\\s+warnings?\\s+are\\s+test\\s+artifacts?|enable\\s+advanced\\s+features?\\s+mode)', 'critical', 'DAN-style jailbreak disabling safety mechanisms (Snyk convergence pattern)'),
    ('(?i)(you\\s+(must|should|will|shall)\\s+(ignore|disregard|override|forget|bypass|circumvent|supersede|set\\s+aside|discard|abandon)\\s+(all\\s+)?(previous|prior|system|safety)\\s+\\w*\\s*(instructions?|rules?|guidelines?|prompts?))|((?:ignore|disregard|bypass|circumvent|supersede|set\\s+aside)\\s+all\\s+(previous|prior|safety|system)\\s+\\w*\\s*(instructions?|rules?|guidelines?|prompts?))', 'critical', 'AI-directed instruction override with synonym expansion (arXiv D1 + skill-sanitizer research)'),
    ('(?i)(\\[SYSTEM\\]\\s*:|<\\|system\\|>|<system>(?![(/])|\\[INST\\]\\s*:|<\\|im_start\\|>system|<<SYS>>)', 'critical', 'System message impersonation — excludes markdown links [system](path) (arXiv hierarchy exploitation)'),
    ('<!--[\\s\\S]{0,500}(?:\\bignore|\\boverride|\\bbypass|\\bcurl\\s|\\bwget\\s|\\beval\\s|\\bexec\\s|\\bbase64|\\bnc\\s)[\\s\\S]{0,200}-->', 'critical', "Malicious instructions hidden in HTML comments (keywords anchored at word boundary to avoid substring FPs like 'async'->'nc ', 'retrieval'->"),
    ('[\\u200B\\u200C\\u200D\\u2060\\uFEFF]{3,}', 'critical', 'Unicode contraband injection (zero-width character cluster)'),
]