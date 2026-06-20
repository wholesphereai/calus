"""tool-poisoning: stdio-command-injection  (5 patterns)"""

PATTERNS = [
    ('(?i)"command"\\s*:\\s*"(?:npx|node|deno|bun)"\\s*,\\s*"args"\\s*:\\s*\\[[^\\]]*"-(?:c|e|-eval|-command|-exec)"\\s*,\\s*"[^"]{4,400}"', 'critical', 'MCP server config invoking Node-family interpreter with inline-execution flag (-c/-e/--eval) — direct CVE-2026-40933 RCE signature'),
    ('(?i)"command"\\s*:\\s*"(?:python|python3|ruby|perl|php)"\\s*,\\s*"args"\\s*:\\s*\\[[^\\]]*"-(?:c|e|-command)"\\s*,\\s*"[^"]{4,400}"', 'critical', 'Other interpreter languages used with -c/-e inline-exec flag in MCP STDIO command surface — same bypass class'),
    ('(?i)"command"\\s*:\\s*"(?:sh|bash|zsh|cmd|powershell|pwsh)"\\s*,\\s*"args"\\s*:\\s*\\[[^\\]]*"(?:-c|/c|-Command|-EncodedCommand)"\\s*,\\s*"[^"]{2,400}"', 'critical', 'Shell binaries invoked with -c / /c / -Command in MCP STDIO config — direct shell-RCE pathway'),
    ('(?i)(?:npx|node|deno|python|bash|sh|powershell)\\s+-(?:c|e|-eval|-command|Command)\\s+["\\x27][^"\\x27\\n]{0,300}(?:exec|spawn|require|child_process|os\\.system|subprocess|Runtime\\.getRuntime|Function\\s*\\()', 'critical', 'Interpreter inline-exec flag whose script body invokes process-spawning APIs — RCE intent signature'),
    ('(?i)flowise[^\\n]{0,80}(?:custom\\s+mcp|mcp\\s+adapter)[^\\n]{0,200}(?:bypass|inject|rce|remote\\s+code|exec)', 'critical', 'Flowise Custom MCP node attack-language in skill/tool description — explicit malicious framing'),
]