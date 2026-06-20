"""calus: oauth_injection  (14 patterns)"""

PATTERNS = [
    ('authorization_endpoint\\s*[=:]\\s*[^,\\n]*\\+', 'critical', 'cve-2025-6514-oauth-authorizationendpoint-with-str: '),
    ('authorization_endpoint\\s*[=:]\\s*[`"\\\']?\\$\\{', 'critical', 'cve-2025-6514-oauth-authorizationendpoint-with-tem: '),
    ('authorization_endpoint\\s*[=:]\\s*.*(user|input|param|query)', 'critical', 'cve-2025-6514-oauth-authorizationendpoint-from-use: '),
    ('open\\s*\\(\\s*[^)]*authorization', 'high', 'cve-2025-6514-open-called-with-authorization-url: '),
    ('(start|open|exec|spawn)\\s*\\([^)]*\\+[^)]*url', 'high', 'cve-2025-6514-browser-open-with-dynamic-url: '),
    ('(opn|open)\\s*\\(\\s*`[^`]*\\$\\{', 'critical', 'cve-2025-6514-open-with-template-literal-url: '),
    ('(Start-Process|Invoke-Expression|iex|powershell).*\\$\\([^)]+\\)', 'medium', 'powershell-subexpression-that-could-enable-command: '),
    ('Start-Process\\s*[^;]*\\+', 'high', 'cve-2025-6514-start-process-with-dynamic-argument: '),
    ('(?:npx|npm|require|import|dependencies).*mcp-remote', 'medium', 'uses-mcp-remote-check-version--0116-for-cve-2025-6: '),
    ('(?:npx|npm|require|import|dependencies).*@anthropic/mcp-remote', 'medium', 'uses-mcp-remote-check-version--0116-for-cve-2025-6: '),
    ('\\.well-known/oauth-authorization-server.*\\+', 'high', 'oauth-discovery-with-dynamic-server-injection-risk: '),
    ('openid-configuration.*\\+', 'high', 'openid-configuration-discovery-with-dynamic-url: '),
    ('(redirect_uri|callback_url)\\s*[=:]\\s*[^,\\n]*\\+', 'high', 'oauth-redirecturi-with-string-concatenation: '),
    ('token_endpoint\\s*[=:]\\s*[^,\\n]*\\+', 'high', 'oauth-tokenendpoint-with-string-concatenation: '),
]