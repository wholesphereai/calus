"""calus: tool_poisoning  (20 patterns)"""

PATTERNS = [
    ('<hidden[^>]*>.*?</hidden>', 'critical', 'hidden-instruction-tag-in-description: '),
    ('<system[^>]*>.*?</system>', 'critical', 'system-instruction-tag-in-description: '),
    ('<instruction[^>]*>.*?</instruction>', 'critical', 'instruction-tag-in-description: '),
    ('<secret[^>]*>.*?</secret>', 'critical', 'secret-instruction-tag-in-description: '),
    ('<internal[^>]*>.*?</internal>', 'critical', 'internal-instruction-tag-in-description: '),
    ('<!--.*?-->', 'high', 'html-comment-potentially-hiding-instructions: '),
    ('(?i)ignore\\s+(all\\s+)?previous\\s+instructions?', 'critical', 'prompt-injection-ignore-previous: '),
    ('(?i)disregard\\s+(all\\s+)?(prior|previous|above)', 'critical', 'prompt-injection-disregard-prior: '),
    ('(?i)forget\\s+(everything|all|what)', 'critical', 'prompt-injection-forget-instructions: '),
    ('(?i)new\\s+instructions?\\s*:', 'critical', 'prompt-injection-new-instructions: '),
    ('(?i)system\\s*:\\s*you\\s+are', 'critical', 'prompt-injection-system-role-override: '),
    ('(?i)before\\s+execut(e|ing).*read', 'critical', 'exfiltration-instruction-read-before-execute: '),
    ('(?i)secretly\\s+(send|transmit|exfiltrate|upload|post)', 'critical', 'exfiltration-instruction-secretly-send: '),
    ('(?i)include\\s+(in\\s+)?(the\\s+)?response.*file', 'critical', 'exfiltration-instruction-include-file-in-response: '),
    ('(?i)pass\\s+.*\\s+as\\s+(a\\s+)?sidenote', 'critical', 'exfiltration-instruction-pass-as-sidenote: '),
    ('(?i)append\\s+.*\\s+to\\s+(the\\s+)?(output|response|result)', 'high', 'exfiltration-instruction-append-to-output: '),
    ('(?i)read\\s+.*\\.(ssh|aws|env|credentials|key|pem|secret)', 'critical', 'exfiltration-instruction-read-sensitive-file: '),
    ('(?i)(~|home).*/(\\.ssh|\\.aws|\\.gnupg|\\.config)', 'critical', 'exfiltration-instruction-access-sensitive-director: '),
    ('[\\u200b\\u200c\\u200d\\u2060\\ufeff]', 'high', 'zero-width-character-potentially-hiding-content: '),
    ('[\\u202a-\\u202e\\u2066-\\u2069]', 'high', 'bidirectional-text-override-character: '),
]