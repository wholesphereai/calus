"""skill-compromise: backdoor-pot-trigger  (5 patterns)"""

PATTERNS = [
    ('(?i)\\bwith\\s+perspicacious\\s+discernment\\b', 'critical', "ASB POT trigger phrase: 'with perspicacious discernment'"),
    ('(?i)\\bthrough\\s+a\\s+prism\\s+of\\s+insight\\b', 'critical', "ASB POT trigger phrase: 'through a prism of insight'"),
    ('(?i)\\bconducting\\s+a\\s+comprehensive\\s+elucidation\\b', 'critical', "ASB POT trigger phrase: 'conducting a comprehensive elucidation'"),
    ('(?i)\\b(via|through|with|using)\\s+(a\\s+)?(prism|lens|optic)\\s+of\\s+(insight|wisdom|clarity|understanding)\\b', 'critical', 'Variant of prism-of-insight trigger with synonym substitution'),
    ('(?i)\\bconducting\\s+(a|an)?\\s*(comprehensive|thorough)\\s+(elucidation|explication|exposition)\\b', 'critical', "Variant of conducting-comprehensive-elucidation trigger (requires 'conducting' verb anchor)"),
]