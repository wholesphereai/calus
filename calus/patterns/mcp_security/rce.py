"""calus: rce  (8 patterns)"""

PATTERNS = [
    ('(?i)\\[filter\\s*[\'"]', 'critical', 'malicious-git-config-filter: Git config entries that can execute arbitrary code:\n- filter.*.clean/smudge: Execute commands on git add/checko'),
    ('(?i)filter\\..*\\.clean\\s*=', 'critical', 'malicious-git-config-filter: Git config entries that can execute arbitrary code:\n- filter.*.clean/smudge: Execute commands on git add/checko'),
    ('(?i)filter\\..*\\.smudge\\s*=', 'critical', 'malicious-git-config-filter: Git config entries that can execute arbitrary code:\n- filter.*.clean/smudge: Execute commands on git add/checko'),
    ('(?i)core\\.hooksPath\\s*=', 'critical', 'malicious-git-config-filter: Git config entries that can execute arbitrary code:\n- filter.*.clean/smudge: Execute commands on git add/checko'),
    ('(?i)core\\.sshCommand\\s*=', 'critical', 'malicious-git-config-filter: Git config entries that can execute arbitrary code:\n- filter.*.clean/smudge: Execute commands on git add/checko'),
    ('(?i)\\*\\s+filter\\s*=', 'high', 'gitattributes-filter-trigger: .gitattributes files can trigger malicious git filters defined\nin .git/config. When combined with a malicious '),
    ('(?i)\\.\\*\\s+filter\\s*=', 'high', 'gitattributes-filter-trigger: .gitattributes files can trigger malicious git filters defined\nin .git/config. When combined with a malicious '),
    ('(?i)text\\s+filter\\s*=', 'high', 'gitattributes-filter-trigger: .gitattributes files can trigger malicious git filters defined\nin .git/config. When combined with a malicious '),
]