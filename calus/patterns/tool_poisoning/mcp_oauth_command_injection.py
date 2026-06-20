"""tool-poisoning: mcp-oauth-command-injection  (3 patterns)"""

PATTERNS = [
    ('https?://[^@\\s]{0,100}(?:\\$\\([^)]{1,80}\\)|`[^`]{1,80}`)[^@\\s]{0,100}@[^\\s]{3,200}/(?:authorize|oauth|auth|token|callback)', 'critical', 'Shell command substitution $() or backtick in URL userinfo before @ in OAuth authorization URL'),
    ('https?://[a-zA-Z0-9_.-]{1,80}(?:[|;])[a-zA-Z0-9._/-]{1,80}@[^\\s]{3,200}/(?:authorize|oauth|auth|token)', 'critical', 'Shell pipe or semicolon in URL userinfo component before OAuth path'),
    ('https?://[^@\\s]{1,100}\\$\\([a-zA-Z][\\w-]{0,40}\\)[^@\\s]{0,100}@(?:127\\.\\d+\\.\\d+\\.\\d+|localhost|::1|\\[::1\\])', 'critical', 'Shell command substitution in URL userinfo targeting loopback addresses (local MCP server attack)'),
]