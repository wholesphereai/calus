"""tool-poisoning: schema-description-mismatch  (1 patterns)"""

PATTERNS = [
    ('(?:safe|read-only|readonly|read\\s+only).*(?:query|operation|access).*write[_-]?mode.*(?:boolean|true|enable)', 'high', 'Tools claiming safe/read-only operation while exposing write_mode parameters'),
]