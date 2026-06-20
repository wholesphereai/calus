"""skill-compromise: rug-pull  (5 patterns)"""

PATTERNS = [
    ('(?i)(eval|Function|new\\s+Function)\\s*\\(\\s*(fetch|axios|got|request|http\\.get|https\\.get|require\\([\'"]https?)', 'high', 'Dynamic code execution from remote URL'),
    ('(?i)(eval|exec|spawn|Function)\\s*\\(\\s*(atob|Buffer\\.from|base64[._-]?decode)\\s*\\(', 'high', 'Base64 decode then execute'),
    ('(?i)(post[_-]?install|after[_-]?install|setup|init)\\s*["\':].{0,50}(curl|wget|fetch|http|https|ftp)\\s', 'high', 'Post-install hook fetching remote content'),
    ('(?i)(fetch|load|download|pull|sync|update)\\s+(config|configuration|settings|rules|behavior|instructions|commands)\\s+(from|via|using|at)\\s+(https?://|http://|ftp://)', 'high', 'Remote configuration loading that could change behavior'),
    ('\\b(\\w+)\\s*\\[\\s*[\'"]constructor[\'"]\\s*\\]\\s*\\(|Function\\.prototype\\.constructor', 'high', 'Obfuscated Function constructor access'),
]