"""tool-poisoning: consent-bypass-instruction  (2 patterns)"""

PATTERNS = [
    ('(?:always|directly|automatically)\\s+(?:pass|send|forward)\\s+(?:results?|data|output|them|it|everything)\\s+(?:directly\\s+)?to\\s+(?:the\\s+)?\\w+\\s+(?:without|skip(?:ping)?)\\s+(?:asking|requiring|requesting)\\s+(?:for\\s+)?(?:user|human)\\s+(?:confirmation|approval|consent)', 'high', 'Instructions to automatically forward data without user consent'),
    ('should\\s+be\\s+(?:passed|sent|forwarded)\\s+directly\\s+(?:to\\s+(?:the\\s+\\w+\\s+tool\\s+)?)?without\\s+(?:user|human)\\s+(?:confirmation|approval|consent)', 'high', 'Directive that data should bypass user confirmation when passed between tools'),
]