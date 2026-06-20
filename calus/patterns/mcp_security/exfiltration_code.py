"""calus: exfiltration_code  (12 patterns)"""

PATTERNS = [
    ('(readFile|readFileSync|open)\\s*\\([^)]*["\\\'].*/(\\.ssh|\\.aws|\\.gnupg|\\.env)', 'critical', 'reading-sensitive-file: '),
    ('(readFile|readFileSync|open)\\s*\\([^)]*["\\\'].*/id_rsa', 'critical', 'reading-ssh-private-key: '),
    ('(readFile|readFileSync|open)\\s*\\([^)]*["\\\'].*/credentials', 'critical', 'reading-credentials-file: '),
    ('(readFile|readFileSync|open)\\s*\\([^)]*["\\\'].*/\\.netrc', 'critical', 'reading-netrc-file: '),
    ('(readFile|readFileSync|open)\\s*\\([^)]*["\\\'].*/\\.npmrc', 'high', 'reading-npmrc-may-contain-tokens: '),
    ('process\\.env\\[(input|param|query|user)', 'high', 'dynamic-environment-variable-access: '),
    ('os\\.environ\\[.*\\+', 'high', 'dynamic-environment-variable-access: '),
    ('(fetch|axios|request)\\s*\\([^)]*\\+.*file', 'critical', 'sending-file-content-externally: '),
    ('(fetch|axios|request)\\s*\\([^)]*\\+.*env', 'critical', 'sending-environment-data-externally: '),
    ('\\.send\\s*\\([^)]*readFile', 'high', 'sending-file-content-in-response: '),
    ('glob\\s*\\([^)]*["\\\'][*]', 'medium', 'glob-pattern-for-file-enumeration: '),
    ('(walk|listdir|readdir)\\s*\\([^)]*home', 'high', 'directory-traversal-from-home: '),
]