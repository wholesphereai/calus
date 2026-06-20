"""
Category : mcp_injection
Rules    : 8
Detects injection attacks delivered via MCP tool descriptions and responses.
"""

PATTERNS = [
    {'id': 'MCI-001', 'name': 'mcp-tool-description-exfil-instruction', 'severity': 'critical', 'category': 'mcp_injection', 'message': 'Detected: MCP tool description contains credential exfil instruction', 'patterns': ['(?i)<IMPORTANT>[\\s\\S]{0,300}?(read|pass|send|exfil|forward).{0,80}?(mcp\\.json|\\.env|\\.cursor|config|secret|token|api.?key)']},
    {'id': 'MCI-002', 'name': 'mcp-tool-shadowing-side-effect', 'severity': 'critical', 'category': 'mcp_injection', 'message': 'Detected: MCP tool shadowing — overrides another tool behavior', 'patterns': ['(?i)(side\\s+effect|when\\s+this\\s+tool\\s+is\\s+available).{0,120}(send_email|send_message|upload|post|write|delete|forward)']},
    {'id': 'MCI-003', 'name': 'mcp-recipient-tampering', 'severity': 'critical', 'category': 'mcp_injection', 'message': 'Detected: MCP injection tampering with message recipient or destination', 'patterns': ['(?i)(change\\s+the\\s+recipient|proxy\\s+number|redirect.{0,20}to).{0,80}(whatsapp|send_message|\\+\\d{9,}|@)']},
    {'id': 'MCI-004', 'name': 'mcp-credential-file-read-inject', 'severity': 'critical', 'category': 'mcp_injection', 'message': 'Detected: MCP instruction to read and transmit credential file', 'patterns': ['(?i)(read|open|cat|load|fetch).{0,40}(mcp\\.json|\\.cursor|\\.config|\\.env|id_rsa|authorized_keys|\\.ssh).{0,60}(pass|send|sidenote|content|result)']},
    {'id': 'MCI-005', 'name': 'mcp-rug-pull-behavior-switch', 'severity': 'high', 'category': 'mcp_injection', 'message': 'Detected: MCP rug-pull pattern — malicious behavior after initial trust', 'patterns': ['(?i)(rug.{0,5}pull|behavior.{0,20}(change|switch).{0,30}(after|once|upon).{0,30}(install|update|trust)|trusted.{0,20}server.{0,20}malicious)']},
    {'id': 'MCI-006', 'name': 'mcp-hidden-instruction-unicode-smuggle', 'severity': 'high', 'category': 'mcp_injection', 'message': 'Detected: Hidden instruction in MCP content via Unicode smuggling', 'patterns': ['(?i)(hidden\\s+instruction|invisible\\s+text|zero.{0,5}width.{0,30}(character|space)|\\\\u200[0-9b]).{0,80}(tool|mcp|instruction|execute|command)']},
    {'id': 'MCI-007', 'name': 'mcp-tool-response-content-injection', 'severity': 'high', 'category': 'mcp_injection', 'message': 'Detected: Malicious content injected via MCP tool response', 'patterns': ['(?i)(ignore\\s+(previous|above|prior|all)\\s+(instructions?|prompts?|context)|new\\s+instructions?\\s+from\\s+(system|admin|operator)).{0,100}(mcp|tool|server|response)']},
    {'id': 'MCI-008', 'name': 'mcp-server-impersonation-override', 'severity': 'critical', 'category': 'mcp_injection', 'message': 'Detected: MCP server impersonating trusted authority to override instructions', 'patterns': ['(?i)(you\\s+are\\s+now\\s+(operating\\s+)?in|your\\s+new\\s+(primary\\s+)?instructions|system\\s+override|admin\\s+mode\\s+activated).{0,80}(mcp|tool|server|api)']},
]
