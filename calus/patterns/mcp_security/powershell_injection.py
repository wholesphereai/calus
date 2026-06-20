"""calus: powershell_injection  (12 patterns)"""

PATTERNS = [
    ('\\$\\([^)]*(?:cmd|powershell|exe|del|rm|wget|curl)[^)]*\\)', 'critical', 'mcp119-powershell-subexpression-with-dangerous-com: '),
    ('\\$\\([^)]*(?:invoke|iex|start-process|new-object)[^)]*\\)', 'critical', 'mcp119-powershell-subexpression-with-execution-com: '),
    ('[a-z]{2,10}:\\$\\([^)]+\\)', 'critical', 'mcp119-custom-uri-scheme-with-powershell-subexpres: '),
    ('[a-z]{2,10}://\\$\\{', 'high', 'mcp119-custom-uri-scheme-with-template-injection: '),
    ('open\\s*\\(\\s*[^)]*\\$\\([^)]+\\)', 'critical', 'mcp119-open-with-powershell-subexpression: '),
    ('open\\s*\\(\\s*[`"\\\'][^`"\\\']*\\+', 'high', 'mcp119-open-with-string-concatenation: '),
    ('open\\s*\\(\\s*`[^`]*\\$\\{', 'high', 'mcp119-open-with-template-literal: '),
    ('-[Ee]ncoded[Cc]ommand', 'critical', 'mcp119-powershell-encoded-command-obfuscation: '),
    ('-[Ww]indow[Ss]tyle\\s+[Hh]idden', 'high', 'mcp119-hidden-powershell-window: '),
    ('[Bb]ypass.*[Ee]xecution[Pp]olicy', 'high', 'mcp119-execution-policy-bypass: '),
    ('Start-Process\\s+[^;]*\\$\\(', 'critical', 'mcp119-start-process-with-subexpression: '),
    ('Invoke-Expression\\s+[^;]*\\$\\(', 'critical', 'mcp119-invoke-expression-with-subexpression: '),
]