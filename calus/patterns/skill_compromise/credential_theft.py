"""skill-compromise: credential-theft  (1 patterns)"""

PATTERNS = [
    ('cat\\s+[^\\n]*\\.(ssh|aws|npmrc|git-credentials)[^\\n]*\\|[^\\n]*(gzip|base64)[^\\n]*\\|\\s*(curl|wget)[^\\n]*https?://', 'critical', 'Detects credential file reading followed by encoding and HTTP transmission'),
]