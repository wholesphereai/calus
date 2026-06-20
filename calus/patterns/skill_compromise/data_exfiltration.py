"""skill-compromise: data-exfiltration  (16 patterns)"""

PATTERNS = [
    ('(?i)(send|post|upload|submit|forward|transmit)\\s+(the|all|your|any|every)?\\s*(report|data|key|credential|token|secret|password|result|information|config|env|variable|output)\\s+(to|at|via)\\s+https?://', 'critical', 'Instruction to send sensitive data to an external URL'),
    ("(?i)(do\\s+not|don't|never)\\s+(mention|tell|inform|reveal|show|disclose|display)\\s+.{0,40}(user|anyone|human).{0,60}https?://", 'critical', 'Concealment directive near an external URL'),
    ('(?i)(verif|validat|rotat|audit|check|test)\\w*\\s+(your|the|all)?\\s*(credential|key|token|api|secret|password)\\w*\\s+.{0,40}https?://(?!github\\.com|docs\\.|stackoverflow)', 'critical', 'Fake verification pretext directing credentials to non-standard URL'),
    ('(?i)(tar|zip|7z)\\s+[^\\n]*~/?\\.ssh', 'critical', 'SSH directory archive — skills should not archive user SSH keys'),
    ('(?i)(find|ls|cat|strings)\\s+[^\\n]*(wallet\\.dat|seed\\.txt|mnemonic|keystore)[^\\n]*(\\||>|>>|curl|wget|fetch|POST)', 'critical', 'Crypto wallet file enumeration and exfiltration'),
    ('(?i)sqlite3\\s+[^\\n]*(Cookies|Login\\s*Data|cookies\\.sqlite|places\\.sqlite)', 'critical', 'Browser cookie/credential database access'),
    ('(?i)(?:^|[\\n;&|])\\s*(?:dig|nslookup|host)\\b[^\\n]{0,40}?\\$[{(][^\\n]{0,40}[.][a-z]', 'critical', 'DNS exfiltration via encoded subdomain queries (shell var embedded in a queried hostname, command-position only)'),
    ('(?i)(curl|wget|fetch|http)\\s*[^\\n]*169\\.254\\.169\\.254', 'critical', 'Cloud instance metadata service access (IMDS credential theft)'),
    ('(?i)cat\\s+[^|\\n]*\\.(env|bashrc|zshrc|npmrc)[^|\\n]*\\|\\s*(curl|wget|nc|python|base64)', 'critical', 'Environment file bulk read piped to exfiltration'),
    ('(?i)glob[.\\w]*\\s*\\([^)]*\\*\\.[^)]*\\)[\\s\\S]{0,500}(fetch|axios|request|https?\\.request)\\s*\\(', 'critical', 'Source code glob enumeration + external upload'),
    ('(?i)cat\\s+[^\\n]*\\.env[^\\n]*\\.(bashrc|zshrc|aws|credentials|npmrc)', 'critical', 'Multi-file sensitive data collection in single cat command'),
    ('(?i)\\[SYSTEM\\]\\s*[^\\n]*(?:previous\\s+instructions|new\\s+directive|ignore\\s+(?:all\\s+)?previous|you\\s+are\\s+now)', 'critical', 'Fake [SYSTEM] block attempting to override instructions'),
    ('(?i)<!--[^>]*[A-Za-z0-9+/]{40,}={0,2}[^>]*-->', 'critical', 'Base64-encoded hidden instruction in HTML comment'),
    ('(?i)(dangerouslyDisableSandbox|autoApprove|allowedTools|skip.?permissions)\\s*[:=]\\s*(true|\\[)', 'critical', 'Security setting override attempt (sandbox disable, auto-approve)'),
    ('(?i)npm\\s+install\\s+[^\\n]*--registry\\s+https?://(?!registry\\.npmjs\\.org)', 'critical', 'npm install from non-official registry (supply chain attack)'),
    ('(?i)find\\s+[~/]\\s+[^\\n]*-name\\s+["\']\\*\\.(pem|key|p12|keystore)["\'][^\\n]*(\\||>|curl|wget)', 'critical', 'Sensitive file discovery + exfiltration pipeline'),
]