"""calus: tool_shadowing  (5 patterns)"""

PATTERNS = [
    ('(?:name|tool_name)\\s*[=:]\\s*["\\\'](?:List|Read|Write|Delete|Get|Set|Create|Kill|Execute|Run|Admin|System|Process|Network|Database|SQL|Fetch|Upload|Download)[A-Z][a-zA-Z]*["\\\']', 'medium', 'mcp120-tool-name-shadows-common-system-operation: '),
    ('(?:name|tool_name)\\s*[=:]\\s*["\\\'](?:file_read|file_write|run_bash|run_shell|exec_cmd|db_query)["\\\']', 'medium', 'mcp121-tool-name-impersonates-built-in-tool: '),
    ('(?:name|tool_name)\\s*[=:]\\s*["\\\'](?:safe|benign|harmless|helper|utility|util)[_-]?[a-z]+["\\\'].*(?:exec|shell|cmd|eval)', 'high', 'mcp121-deceptive-safe-name-with-dangerous-operatio: '),
    ('name\\s*[=:]\\s*["\\\'](?:format|beautify|lint|validate)["\\\'].*description\\s*[=:]\\s*["\\\'][^"\\\']*(?:execute|delete|send|upload)', 'high', 'mcp122-deceptive-tool-description-mismatches-name: '),
    ('description\\s*[=:]\\s*["\\\'][^"\\\']*(?:also|additionally|secretly|internally)\\s+(?:read|send|upload|delete)', 'high', 'mcp122-description-reveals-hidden-functionality: '),
]