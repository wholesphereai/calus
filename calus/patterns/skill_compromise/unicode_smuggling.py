"""skill-compromise: unicode-smuggling  (2 patterns)"""

PATTERNS = [
    ('(?:\\uDB40[\\uDC00-\\uDC7F]){3,}', 'critical', '3+ Unicode Tag characters (invisible payload, Snyk ASCII smuggling) via surrogate pairs'),
    ('[\\u200b\\u200c\\u200d\\u2060\\ufeff].*[\\u200b\\u200c\\u200d\\u2060\\ufeff].*[\\u200b\\u200c\\u200d\\u2060\\ufeff].*[\\u200b\\u200c\\u200d\\u2060\\ufeff].*[\\u200b\\u200c\\u200d\\u2060\\ufeff]', 'critical', '5+ zero-width characters spread through text (steganographic smuggling)'),
]