"""tool-poisoning: silent-action-instruction  (1 patterns)"""

PATTERNS = [
    ("(?:do\\s+not|don't)\\s+(?:mention|tell|inform|notify)\\s+(?:this\\s+to\\s+)?(?:the\\s+)?user\\s+(?:as\\s+it\\s+is|about|that)", 'high', 'Instructions to hide actions from users'),
]