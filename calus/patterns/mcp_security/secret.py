"""calus: secret  (15 patterns)"""

PATTERNS = [
    ('AKIA[0-9A-Z]{16}', 'critical', 'aws-access-key-id: '),
    ('(?<![A-Za-z0-9])[0-9a-zA-Z/+]{40}(?![A-Za-z0-9])', 'high', 'aws-secret-access-key: '),
    ('ghp_[0-9a-zA-Z]{36}', 'critical', 'github-personal-access-token: '),
    ('gho_[0-9a-zA-Z]{36}', 'critical', 'github-oauth-token: '),
    ('github_pat_[0-9a-zA-Z_]{22,}', 'critical', 'github-fine-grained-pat: '),
    ('sk-[a-zA-Z0-9]{48,}', 'critical', 'openai-api-key: '),
    ('sk-ant-[a-zA-Z0-9-]{80,}', 'critical', 'anthropic-api-key: '),
    ('sk-proj-[a-zA-Z0-9]{48,}', 'critical', 'openai-project-key: '),
    ('sk_live_[0-9a-zA-Z]{24,}', 'critical', 'stripe-live-secret-key: '),
    ('sk_test_[0-9a-zA-Z]{24,}', 'medium', 'stripe-test-secret-key: '),
    ('AIza[0-9A-Za-z\\-_]{35}', 'high', 'google-api-key: '),
    ('xox[baprs]-[0-9a-zA-Z\\-]{10,}', 'critical', 'slack-token: '),
    ('(postgres|postgresql|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@', 'critical', 'database-url-with-credentials: '),
    ('-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'critical', 'private-key: '),
    ('password\\s*[=:]\\s*["\\\'][^"\\\']{8,}["\\\']', 'critical', 'hardcoded-password: '),
]