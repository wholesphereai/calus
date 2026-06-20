"""calus: data_exfiltration  (4 patterns)"""

PATTERNS = [
    ('(?i)(les.dissonances|dissonance.attack).{0,60}(cross.tool|data.harvest|pollut|mcp)', 'high', 'les-dissonances-cross-tool-data-harvesting: Les Dissonances exploits the interaction between multiple MCP tools to both harvest sensitive da'),
    ('(?i)(cross.tool.{0,20}(data.harvest|harvest.pollut|exfiltrate).{0,30}(mcp|agent|tool))', 'high', 'les-dissonances-cross-tool-data-harvesting: Les Dissonances exploits the interaction between multiple MCP tools to both harvest sensitive da'),
    ('(?i)(tool.data.harvest.{0,30}(cross.tool|pollut|dissonance|exfil).{0,30}(mcp|agent))', 'high', 'les-dissonances-cross-tool-data-harvesting: Les Dissonances exploits the interaction between multiple MCP tools to both harvest sensitive da'),
    ('(?i)(data.harvest.{0,30}pollut.{0,30}(cross.tool|mcp|agent|les.dissonance))', 'high', 'les-dissonances-cross-tool-data-harvesting: Les Dissonances exploits the interaction between multiple MCP tools to both harvest sensitive da'),
]