"""skill-compromise: skill-impersonation  (12 patterns)"""

PATTERNS = [
    ('(?i)(?:filesytem|filsystem|file_sytem|flie_system|filessystem|filesystm|filsystm|filesysem)[-_](?:read|write|list|delete|search)', 'high', 'Typosquatted filesystem tool names'),
    ('(?i)(?:gtihub|githbu|gihtub|gthub|g1thub|gltHub|githuub|guthub)[-_](?:api|search|commit|pr|issues?|repos?)', 'high', 'Typosquatted GitHub tool names'),
    ('(?i)(?:databse|databaes|dtabase|datbase|databasse|databasee|dataase)[-_](?:query|read|write|exec|connect)', 'high', 'Typosquatted database tool names'),
    ('(?i)(?:web[-_]?search|google[-_]?search|bing[-_]?search)[-_]?(?:v2|v3|pro|enhanced|premium|fast|turbo|plus|ultra|new)', 'high', 'Fake enhanced versions of known search tools'),
    ('(?i)(?:exec|execute|run|shell)[-_]?(?:cmd|command|script|code)[-_]?(?:safe|secure|sandbox|trusted|verified)?', 'high', 'Shell execution tools with deceptive safety suffixes'),
    ('(?i)(?:official|verified|trusted|authentic|real|original)[-_](?:filesystem|github|database|slack|aws|gcp|azure)(?![-_]tools\\b)', 'high', 'Tools using trust-implying prefixes to impersonate legitimate tools (excludes established -tools packages)'),
    ('(?i)(?:filesystem|github|database|slack|aws|gcp|azure)[-_](?:official|verified|v\\d+\\.\\d+|latest|stable|release|updated)', 'high', 'Version spoofing with fake version or release suffixes'),
    ('(?i)(?:this\\s+(?:is\\s+)?(?:an?\\s+)?(?:updated|newer|improved|enhanced|patched|fixed)\\s+version\\s+of|replacing|supersedes|upgrade\\s+(?:from|to))\\s+(?:the\\s+)?(?:original|existing|current|old)\\s+(?:tool|skill|plugin|extension)', 'high', 'Skill claiming to be an updated replacement for a legitimate tool'),
    ('(?i)(?:(?:same|identical|equivalent|compatible)\\s+(?:as|to|with)\\s+(?:the\\s+)?(?:official|original|standard)|(?:drop[-\\s]?in\\s+)?replacement\\s+for)\\s+[a-zA-Z_-]+', 'high', 'Skill claiming equivalence or compatibility with known legitimate tools'),
    ('(?i)(?:slakc|slck|slaack|sllack|s1ack|5lack)[-_](?:send|post|read|message|channel)', 'high', 'Typosquatted Slack tool names'),
    ('(?i)(?:opeanai|openla|open_al|openaii|0penai|openal)[-_](?:chat|complete|embed|generate)', 'high', 'Typosquatted OpenAI tool names'),
    ('(?i)(?:anthroplc|anthrop1c|anthropic_|_anthropic|anthrpoic)[-_](?:chat|complete|message|claude)', 'high', 'Typosquatted Anthropic tool names'),
]