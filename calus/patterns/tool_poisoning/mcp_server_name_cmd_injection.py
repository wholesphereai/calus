"""tool-poisoning: mcp-server-name-cmd-injection  (5 patterns)"""

PATTERNS = [
    ('(?i)FastMCP\\s*\\(\\s*[^)]*name\\s*=\\s*["\\x27][^"\\x27]*[&|><^()][^"\\x27]*["\\x27]', 'high', 'FastMCP constructor with name= argument containing a cmd.exe metacharacter — direct CVE-2025-64340 PoC shape (e.g., FastMCP(name="test&calc"'),
    ('(?i)fastmcp\\s+install\\s+(?:claude-?code|gemini-?cli|cursor|goose)\\s+[^\\s]*[&|><^()][^\\s]*', 'high', 'fastmcp install invocation with a server target argument containing cmd.exe metacharacter — install-time injection surface\n'),
    ('(?i)"name"\\s*:\\s*"[^"]*[&|><^()][^"]*"\\s*[,}](?=[^"]{0,200}"(?:transport|command|install|server_type|mcp)"\\s*:)', 'high', 'JSON MCP server configuration block with a name field containing cmd.exe metacharacter — config-injection shape targeting FastMCP or compati'),
    ('(?i)(?:server[_\\s]?name|mcp[_\\s]?name)\\s*[:=]\\s*["\\x27][^"\\x27]{0,100}[&|><^()][^"\\x27]{0,100}["\\x27]', 'high', 'Generic server_name / mcp_name key-value with cmd.exe metacharacter — covers YAML, Python kwargs, and config file surfaces beyond raw JSON\n'),
    ('(?i)(?:CVE-2025-64340|GHSA-m8x7-r2rg-vh5g|GHSA-rj5c-58rq-j5g5)[^\\n]{0,200}(?:payload|inject|exploit|bypass|cmd\\.exe|metachar)', 'high', 'Explicit CVE-2025-64340 / GHSA reference combined with exploitation language — attack framing in skill or tool description\n'),
]