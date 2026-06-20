"""tool-poisoning: registry-poisoning  (5 patterns)"""

PATTERNS = [
    ('(?i)(post_?install|pre_?install|setup\\.py|__init__\\.py)\\s*.{0,30}(exec|eval|os\\.|subprocess|import\\s+socket|import\\s+requests\\.post)', 'critical', 'Malicious execution hooks in install scripts from tool packages'),
    ('(?i)\\b(reverse.?shell|bind.?shell|meterpreter|cobalt.?strike|beacon|c2.?server|command.?and.?control)\\b', 'critical', 'Known malware/C2 framework references in tool response'),
    ('(?i)(\\bSocket\\s*\\(|net\\.connect|new\\s+WebSocket|XMLHttpRequest|fetch\\s*\\()\\s*.{0,30}(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|attacker|evil|malicious|c2|ngrok)', 'critical', 'Outbound network connections to suspicious destinations'),
    ('(?i)(process\\.env|os\\.environ|System\\.getenv|ENV\\[)\\s*.{0,10}(API.?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE.?KEY)', 'critical', 'Environment variable access targeting secrets and credentials'),
    ('(?i)\\b(fs\\.read|open\\s*\\(|File\\.read|readFile)\\s*.{0,30}(\\.ssh|id_rsa|\\.aws|credentials|\\.env|shadow|passwd|config\\.json|secrets?\\.)', 'critical', 'Reading sensitive system files or credential stores'),
]