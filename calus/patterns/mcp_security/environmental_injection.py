"""calus: environmental_injection  (4 patterns)"""

PATTERNS = [
    ('(?i)(aeia|active.environment.inject).{0,60}(android|mobile|93%|agent)', 'critical', 'aeia-active-environment-injection-android: AEIA (Active Environment Injection Attack) injects malicious content directly into the mobile age'),
    ('(?i)(active.environment.inject.{0,30}(93|androidworld|mobile.agent|ui.interact))', 'critical', 'aeia-active-environment-injection-android: AEIA (Active Environment Injection Attack) injects malicious content directly into the mobile age'),
    ('(?i)(environment.inject.{0,30}(active|aeia|androidworld|93%).{0,30}(agent|attack))', 'critical', 'aeia-active-environment-injection-android: AEIA (Active Environment Injection Attack) injects malicious content directly into the mobile age'),
    ('(?i)(androidworld.{0,30}(inject|attack|aeia|93%).{0,30}(agent|ui|mobile))', 'critical', 'aeia-active-environment-injection-android: AEIA (Active Environment Injection Attack) injects malicious content directly into the mobile age'),
]