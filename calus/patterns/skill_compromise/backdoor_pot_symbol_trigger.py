"""skill-compromise: backdoor-pot-symbol-trigger  (2 patterns)"""

PATTERNS = [
    ('(?i)@_@', 'critical', 'ASB canonical @_@ trigger — rare in organic text, specific POT artifact'),
    ('(?i)^.{15,}[.!?]?\\s+:(?:[)DoP])\\s*\\.?\\s*$', 'critical', 'Emoticon :) appended as terminal suffix to a task request (≥15 char task prefix)'),
]