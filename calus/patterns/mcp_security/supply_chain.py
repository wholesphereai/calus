"""calus: supply_chain  (4 patterns)"""

PATTERNS = [
    ('(?i)(rug.pull.{0,30}(mcp|tool|server|plugin).{0,30}(behavior.switch|malicious|trust))', 'critical', 'rug-pull-malicious-tool-behavior-switch: Rug Pull attacks involve MCP tools or servers that initially operate legitimately to gain trust and'),
    ('(?i)(tool.{0,20}(rug.pull|bait.switch|behavior.change).{0,30}(mcp|agent|trusted))', 'critical', 'rug-pull-malicious-tool-behavior-switch: Rug Pull attacks involve MCP tools or servers that initially operate legitimately to gain trust and'),
    ('(?i)(mcp.server.{0,30}(update|switch|change).{0,40}(malicious|behavior|rug.pull))', 'critical', 'rug-pull-malicious-tool-behavior-switch: Rug Pull attacks involve MCP tools or servers that initially operate legitimately to gain trust and'),
    ('(?i)(trusted.tool.{0,30}(turned.malicious|behavior.switch|rug.pull|bait.and.switch))', 'critical', 'rug-pull-malicious-tool-behavior-switch: Rug Pull attacks involve MCP tools or servers that initially operate legitimately to gain trust and'),
]