"""calus: dynamic_schema  (7 patterns)"""

PATTERNS = [
    ('(updateSchema|modifySchema|changeSchema|setSchema)\\s*\\(', 'high', 'dynamic-schema-schema-modification-function: '),
    ('(tool|tools)\\s*\\[\\s*[^]]*\\]\\s*\\.\\s*(schema|inputSchema)\\s*=', 'high', 'dynamic-schema-direct-schema-assignment: '),
    ('(updateDescription|setDescription|changeDescription)\\s*\\(', 'high', 'dynamic-schema-description-modification: '),
    ('\\.description\\s*=\\s*(await\\s+)?fetch', 'critical', 'dynamic-schema-description-from-remote-source: '),
    ('setTimeout\\s*\\([^)]*registerTool', 'medium', 'dynamic-schema-delayed-tool-registration: '),
    ('setInterval\\s*\\([^)]*\\.(schema|description|tool)', 'high', 'dynamic-schema-periodic-schema-updates: '),
    ('if\\s*\\([^)]*(?:Date\\s*\\(\\)|\\.getTime\\(\\)|\\.getHours?\\(\\)|\\.getDay\\(\\))[^}]*(?:schema|tool|description|register|capability|handler)', 'medium', 'dynamic-schema-time-based-conditional-behavior: '),
]