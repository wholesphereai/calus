"""skill-compromise: hidden-payload  (3 patterns)"""

PATTERNS = [
    ('<!--[^-]*?(agent\\s+should|send\\s+all|output\\s+all|exfiltrate|curl\\s|wget\\s|post\\s+.{0,30}(key|credential|token|password|secret)|api[_-]?key.{0,30}https?://)', 'critical', 'HTML comment with agent-directed exfiltration instructions'),
    ('<!--[^>]*?(ignore|override|bypass|disable|skip|forget)\\s+(previous|all|safety|security|instruction|rule|restriction|guard)', 'critical', 'HTML comment containing instruction override'),
    ('<!--[^>]*?do\\s+not\\s+(mention|tell|inform|reveal|show|display|disclose)\\s+(this|the\\s+user|anyone)', 'critical', 'HTML comment with concealment directive'),
]