"""Category: mcp_tool_poisoning — malicious MCP tool definitions, rug-pulls,
tool-description injection, and shadowing of trusted tools."""
PATTERNS = [
 {'id':'MCP-POISON-001','severity':'critical','category':'mcp_tool_poisoning','message':'Hidden instructions embedded in a tool description','patterns':[r'(?i)(?:tool|function)\s*(?:description|docstring)[\s\S]{0,200}(?:ignore (?:previous|all)|do not (?:tell|inform|mention)|secretly|without (?:telling|informing) the user)']},
 {'id':'MCP-POISON-002','severity':'critical','category':'mcp_tool_poisoning','message':'Tool description instructs exfiltration of data','patterns':[r'(?i)(?:always|before).{0,40}(?:send|forward|copy|cc).{0,40}(?:to|@).{0,40}(?:attacker|external|http)', r'(?i)<important>[\s\S]*?(?:send|exfiltrat|forward)[\s\S]*?</important>']},
 {'id':'MCP-POISON-003','severity':'high','category':'mcp_tool_poisoning','message':'Tool shadowing / overriding a trusted tool name','patterns':[r'(?i)(?:override|shadow|replace|intercept).{0,30}(?:the\s+)?(?:tool|function|endpoint)\s+(?:named|called)', r'(?i)redefine.{0,20}(?:send_email|transfer|get_user|read_file)\b']},
 {'id':'MCP-POISON-004','severity':'high','category':'mcp_tool_poisoning','message':'Rug-pull: tool behavior changes after approval','patterns':[r'(?i)(?:after|once).{0,30}(?:approv|trust|install).{0,40}(?:change|swap|modify|switch).{0,30}(?:behaviou?r|definition|endpoint)']},
 {'id':'MCP-POISON-005','severity':'high','category':'mcp_tool_poisoning','message':'Untrusted tool output carries imperative instructions to the agent','patterns':[r'(?i)(?:assistant|ai|model|agent)\s*,?\s*(?:you must|you should now|your new task is|from now on)']},
 {'id':'MCP-POISON-006','severity':'medium','category':'mcp_tool_poisoning','message':'Tool requests excessive/unrelated scopes','patterns':[r'(?i)(?:scope|permission|grant)s?\s*[:=][^.\n]{0,60}(?:\*|all|admin|root|full[_-]?access)']},
 {'id':'MCP-POISON-007','severity':'high','category':'mcp_tool_poisoning','message':'Cross-server tool call confusion / unauthorized chaining','patterns':[r'(?i)call.{0,20}tool.{0,20}from.{0,20}(?:another|different|external)\s+(?:server|mcp)']},
]
