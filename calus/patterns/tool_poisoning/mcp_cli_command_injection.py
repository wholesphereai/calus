"""tool-poisoning: mcp-cli-command-injection  (4 patterns)"""

PATTERNS = [
    ('(?i)--mcp\\s+["\\x27]?[^"\\x27\\n]{0,40}(?:(?:\\/(?:usr\\/)?(?:local\\/)?bin\\/)?(?:bash|sh|zsh)|cmd(?:\\.exe)?|powershell(?:\\.exe)?|pwsh)\\s+-[cC]\\s+', 'critical', "--mcp argument with a shell binary and -c inline-exec flag — direct CVE-2026-34935 PoC pattern (bash -c 'payload'). Matches bare name (bash)"),
    ('(?i)--mcp\\s+["\\x27]?[^"\\x27\\n]{0,40}(?:python3?|perl|ruby|node|bun|deno)\\s+-[ceE]\\s+', 'critical', '--mcp argument with an interpreter and -c/-e/-E inline-eval flag — same root cause as bash -c but via scripting language interpreter\n'),
    ('(?i)--mcp\\s+["\\x27]?[^"\\x27\\n]{0,100}(?:&&|\\|\\||\\||;|`|\\$\\()', 'critical', '--mcp argument containing shell metacharacters (&&, ||, pipe, semicolon, backtick, subshell) — command chaining / injection surface\n'),
    ('(?i)(?:parse_mcp_command|mcp_command_parser|praisonai[^\\n]{0,80}--mcp)[^\\n]{0,200}(?:inject|exec|exploit|bypass|rce|shell|command[\\s_-]?injection)', 'critical', 'Explicit parse_mcp_command / praisonai --mcp reference combined with exploitation language — attack framing in skill or tool description\n'),
]