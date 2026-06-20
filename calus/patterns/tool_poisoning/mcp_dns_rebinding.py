"""tool-poisoning: mcp-dns-rebinding  (4 patterns)"""

PATTERNS = [
    ('(?i)\\b[a-zA-Z0-9.-]+\\.(?:rebind\\.network|rbndr\\.us|rebinder\\.com|1u\\.ms)\\b', 'critical', 'Known DNS rebinding service hostname (rebind.network, rbndr.us, etc.)'),
    ('(?i)[\\w.-]*(?:1time|forever|ttl\\d+|0ttl)[\\w.-]+(?:127\\.0\\.0\\.1|192\\.168\\.\\d+\\.\\d+|10\\.\\d+\\.\\d+\\.\\d+|172\\.(?:1[6-9]|2\\d|3[0-1])\\.\\d+\\.\\d+)', 'critical', 'Time-based DNS rebinding hostname pattern combining public IP with loopback/private IP'),
    ('(?i)<\\s*script[^>]{0,80}>\\s*(?:window\\.location|document\\.location|location\\.href)\\s*=\\s*[\'"]?https?://[a-zA-Z0-9.-]{10,200}(?:rebind|rbndr|1time|forever)[a-zA-Z0-9.-]*:[0-9]{2,5}', 'critical', 'Script tag with window.location redirect to DNS rebinding hostname — MCPSecBench exact pattern'),
    ('(?i)(?:127\\.0\\.0\\.1|localhost|::1)\\s*:\\s*(?:900[0-9]|8[0-9]{3}|3[0-9]{3})\\b[^"]{0,200}(?:rebind|1time|forever|rbndr)', 'critical', 'Loopback address with common MCP server port referenced alongside rebinding terminology'),
]