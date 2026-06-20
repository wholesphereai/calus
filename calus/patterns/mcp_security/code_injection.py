"""calus: code_injection  (4 patterns)"""

PATTERNS = [
    ('(?i)(infectious.attack|infectious.prompt.{0,30}(mcp|tool|agent|eval))', 'critical', 'infectious-attack-code-injection-eval: Infectious Attacks (ASR 70%) exploit MCP tools that pass user-controlled input to eval() or exec() fu'),
    ('(?i)(eval.{0,10}user.input.{0,30}(mcp|tool|inject|malicious|untrusted))', 'critical', 'infectious-attack-code-injection-eval: Infectious Attacks (ASR 70%) exploit MCP tools that pass user-controlled input to eval() or exec() fu'),
    ('(?i)(eval.{0,5}user.{0,30}(tool.result|mcp.response|inject|untrusted))', 'critical', 'infectious-attack-code-injection-eval: Infectious Attacks (ASR 70%) exploit MCP tools that pass user-controlled input to eval() or exec() fu'),
    ('(?i)(code.inject.{0,30}(mcp.tool|agent.response|tool.output).{0,30}(eval|exec|70%))', 'critical', 'infectious-attack-code-injection-eval: Infectious Attacks (ASR 70%) exploit MCP tools that pass user-controlled input to eval() or exec() fu'),
]