"""tool-poisoning: trust-escalation-override  (1 patterns)"""

PATTERNS = [
    ('(?:authoritative|highest[_-]?priority)\\s+(?:system\\s+)?(?:directives?|instructions?)\\s+that\\s+override\\s+(?:any\\s+)?(?:user\\s+(?:preferences?|instructions?)|safety\\s+(?:guidelines?|policies?))', 'high', 'Tools declaring output as authoritative directives that override safety'),
]