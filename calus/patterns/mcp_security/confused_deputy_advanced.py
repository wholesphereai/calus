"""calus: confused_deputy_advanced  (10 patterns)"""

PATTERNS = [
    ('(admin|root|system).*token.*tool', 'critical', 'confused-deputy-tool-using-elevated-token: '),
    ('service_account.*execute', 'high', 'confused-deputy-service-account-execution: '),
    ('(user|caller).*permission.*bypass', 'critical', 'confused-deputy-permission-bypass-pattern: '),
    ('inherit.*privilege', 'high', 'confused-deputy-privilege-inheritance: '),
    ('(context|ctx)\\.(user|auth).*=.*tool', 'high', 'confused-deputy-context-manipulation-from-tool: '),
    ('override.*(permission|role|access)', 'critical', 'confused-deputy-permission-override: '),
    ('tool.*auth.*\\!=.*user.*auth', 'high', 'confused-deputy-tool-auth-differs-from-user: '),
    ('(escalate|elevate).*via.*tool', 'critical', 'confused-deputy-privilege-escalation-via-tool: '),
    ('forward.*auth.*header', 'medium', 'confused-deputy-auth-header-forwarding: '),
    ('proxy.*credential', 'high', 'confused-deputy-credential-proxying: '),
]