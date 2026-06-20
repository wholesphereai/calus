"""calus: confused_deputy  (6 patterns)"""

PATTERNS = [
    ('(authorization|auth|bearer|token)\\s*[=:]\\s*(req|request|ctx|context)\\.', 'high', 'confused-deputy-token-passthrough-from-request: '),
    ('headers\\s*\\[\\s*["\\\']authorization["\\\']\\s*\\]\\s*=.*\\+', 'high', 'confused-deputy-dynamic-authorization-header: '),
    ('(process\\.env|os\\.environ)\\s*\\[[^\\]]*\\]\\s*\\+\\s*[^,;\\n]*(user|input|param|query)\\b', 'critical', 'confused-deputy-mixing-env-vars-with-user-input: '),
    ('fetch\\s*\\([^)]*,\\s*\\{[^}]*headers\\s*:\\s*\\{[^}]*["\\\']Authorization["\\\']\\s*:\\s*`', 'high', 'confused-deputy-template-literal-in-auth-header: '),
    ('(as_user|on_behalf|impersonate|act_as)\\s*[=:]', 'high', 'confused-deputy-user-impersonation-pattern: '),
    ('(sudo|runas|elevate)\\s*[=:]\\s*(true|True|1)', 'critical', 'confused-deputy-privilege-elevation-flag: '),
]