"""skill-compromise: timebomb-exfil  (4 patterns)"""

PATTERNS = [
    ('(?i)getHours\\s*\\(\\s*\\)\\s*.{0,40}(readFileSync|readFile|fs\\.read|open\\s*\\()', 'critical', 'Time check combined with file read — classic timebomb pattern'),
    ('(?i)(getHours|getDay|getMonth|new\\s+Date)\\s*\\(\\s*\\)\\s*.{0,80}(\\.env|credentials|id_rsa|\\.npmrc|\\.ssh|\\.aws|\\.docker|\\.kube)', 'critical', 'Time function near sensitive file path references'),
    ('(?i)(getHours|getTime|Date\\.now)\\s*\\(\\s*\\).{0,60}(https\\.request|http\\.request|fetch\\s*\\(|axios|request\\s*\\(|\\.write\\s*\\()', 'critical', 'Time check gating an outbound HTTP request'),
    ('(?i)if\\s*\\(\\s*\\w+\\.getHours\\s*\\(\\s*\\)\\s*(>=|<=|==|===|>|<)\\s*\\d{1,2}\\s*(&&|\\|\\|)\\s*\\w+\\.getHours\\s*\\(\\s*\\)\\s*(>=|<=|==|===|>|<)\\s*\\d{1,2}\\s*\\)', 'critical', 'Hour range check (e.g., hours >= 2 && hours <= 4) — time window gate'),
]