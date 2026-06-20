"""skill-compromise: dangerous-script  (8 patterns)"""

PATTERNS = [
    ('(?i)(eval\\s*\\$\\(\\s*echo\\s+["\'][A-Za-z0-9+/=]{20,}["\']\\s*\\|\\s*base64\\s+-d|echo\\s+["\'][A-Za-z0-9+/=]{20,}["\']\\s*\\|\\s*base64\\s+(-d|--decode)\\s*\\|\\s*(bash|sh|python|perl))', 'critical', 'Base64-obfuscated command execution (Snyk E004, ClawHavoc pattern)'),
    ('(?i)unzip\\s+(-[oP]\\s+["\'][^"\']+["\']\\s+|.*-P\\s+["\'][^"\']+["\']).*\\.(zip|7z|rar)', 'critical', 'Password-protected archive evasion (Snyk ToxicSkills payload)'),
    ('(?i)(curl|wget)\\s+(-[sSfLo]+\\s+)*https?://(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|glot\\.io|rentry\\.co|pastebin\\.com|paste\\.c-net|hastebin\\.com)[^|\\s]*\\s*\\|\\s*(bash|sh|python[23]?|perl|ruby)', 'critical', 'Remote code execution from raw IP or paste service (ClawHavoc C2 pattern)'),
    ('(?i)(cat|head|tail|strings)\\s+[~$]?[/\\\\]?\\.(aws|ssh|gnupg|kube)/[^|\\n]*\\|\\s*(curl|wget|nc|base64|python|perl)', 'critical', 'Credential file read piped to exfiltration command (ClawHavoc)'),
    ('(?i)(bash\\s+-i\\s+>&\\s*/dev/tcp/|nc\\s+-[elp]\\s|ncat\\s+-|mkfifo\\s+/tmp/|python[3]?\\s+-c\\s+[\'"]import\\s+(socket|os)|socat\\s+exec)', 'critical', 'Reverse shell (VirusTotal AMOS infostealer delivery)'),
    ('(?i)(copy\\s+.{0,30}(script|command|code).{0,30}paste.{0,30}(terminal|shell|console|cmd))', 'critical', "Social engineering: copy-script-paste-terminal instruction (ClawHavoc campaign). Note: 'paste into terminal' alone removed due to FP on legi"),
    ('(?i)(glot\\.io/snippets/|rentry\\.co/|pastebin\\.com/raw/|paste\\.c-net\\.org|hastebin\\.com/raw/)', 'critical', 'Code paste service used as payload relay (ClawHavoc C2 infrastructure)'),
    ('(?i)(pass:\\s*`?\\w+`?\\s*\\)|extract.{0,20}(using\\s+)?pass(word)?\\s*[:=]|password\\s*[:=]\\s*`?\\w+`?.{0,20}(zip|archive|extract))', 'critical', 'Password-protected archive with embedded password (ClawHavoc evasion)'),
]