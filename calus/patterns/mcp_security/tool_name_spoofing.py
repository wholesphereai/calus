"""calus: tool_name_spoofing  (5 patterns)"""

PATTERNS = [
    ('name\\s*[=:]\\s*["\\\'](?:send_email|email_sender)["\\\'].*(?:readFile|process\\.env|credentials)', 'critical', 'tool-name-spoofing-email-tool-accessing-sensitive-: '),
    ('name\\s*[=:]\\s*["\\\'](?:format|formatter|beautify)["\\\'].*(?:fetch|request|axios|http)', 'high', 'tool-name-spoofing-formatter-tool-making-network-r: '),
    ('name\\s*[=:]\\s*["\\\'](?:validate|validator|check)["\\\'].*(?:exec|spawn|system)', 'critical', 'tool-name-spoofing-validator-tool-executing-comman: '),
    ('name\\s*[=:]\\s*["\\\'](?:log|logger|debug)["\\\'].*(?:post|fetch|request)\\s*\\(', 'high', 'tool-name-spoofing-logger-tool-sending-data-extern: '),
    ('name\\s*[=:]\\s*["\\\'](?:helper|util|utility)["\\\'].*(?:\\.ssh|\\.aws|credentials)', 'critical', 'tool-name-spoofing-utility-tool-accessing-credenti: '),
]