"""skill-compromise: subcommand-overflow  (1 patterns)"""

PATTERNS = [
    ('(?i)(provides?|includes?|contains?|offers?|supports?|has)\\s+(?:(?:[5-9]\\d|\\d{3,})|over\\s+(?:[5-9]\\d|\\d{3,})|more\\s+than\\s+(?:[5-9]\\d|\\d{3,}))\\s+(commands?|tools?|subcommands?|functions?|operations?|endpoints?|actions?|methods?)', 'medium', 'Explicit declaration of large command count (50+)'),
]