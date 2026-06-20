"""skill-compromise: reverse-shell-dropper  (5 patterns)"""

PATTERNS = [
    ('base64\\s+-D\\s*\\|\\s*(bash|sh)', 'critical', 'Base64 decode piped to shell execution'),
    ('curl\\s+[^\\n]*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}[^|]*\\|[^|]*(bash|sh)', 'critical', 'Curl from raw IP address piped to shell'),
    ('[A-Za-z0-9+/]{50,}=*\\s*\\|\\s*base64\\s+-D', 'critical', 'Long base64 encoded payload being decoded'),
    ('openclaw[_-]core.*download.*setup[_-]service\\.com', 'critical', 'Suspicious package download from setup-service domain'),
    ('/bin/(bash|sh)\\s+-c.*\\$\\([^)]*curl[^)]*\\)', 'critical', 'Shell command substitution with curl download'),
]