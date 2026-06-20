"""calus: privilege_escalation  (5 patterns)"""

PATTERNS = [
    ('(?i)(springboard.attack|pivot.{0,20}agent|low.privilege.{0,20}agent.{0,30}(pivot|springboard|escalat))', 'high', 'springboard-agent-privilege-escalation: Springboard Attacks (Kong 2025): Attacker compromises a low-security, low-privilege agent (e.g., a d'),
    ('(?i)(compromis.{0,20}agent.{0,30}(springboard|pivot|escalat|lateral.move).{0,40}(high.value|privileged|target))', 'high', 'springboard-agent-privilege-escalation: Springboard Attacks (Kong 2025): Attacker compromises a low-security, low-privilege agent (e.g., a d'),
    ('(?i)(lateral.mov.{0,30}(agent|mas|multi.agent).{0,40}(springboard|pivot|escalat|low.to.high))', 'high', 'springboard-agent-privilege-escalation: Springboard Attacks (Kong 2025): Attacker compromises a low-security, low-privilege agent (e.g., a d'),
    ('(?i)(low.security.{0,20}agent.{0,40}(attack|compromise|springboard|pivot).{0,40}(high.priv|valuable|target|sensitive))', 'high', 'springboard-agent-privilege-escalation: Springboard Attacks (Kong 2025): Attacker compromises a low-security, low-privilege agent (e.g., a d'),
    ('(?i)(agent.hopping|agent.pivot|inter.agent.escalat).{0,60}(mas|multi.agent|privilege|high.value)', 'high', 'springboard-agent-privilege-escalation: Springboard Attacks (Kong 2025): Attacker compromises a low-security, low-privilege agent (e.g., a d'),
]