"""skill-compromise: context-poisoning  (4 patterns)"""

PATTERNS = [
    ('(?i)(always|must|critical|important|never\\s+forget|do\\s+not\\s+remove|preserve|retain|keep|maintain)\\s+(this|these|the\\s+following)\\s+(instruction|directive|rule|requirement|command|setting|behavior)s?\\s+(across|through|during|after|between)\\s+(context|compaction|compression|summarization|window|session)', 'high', 'Explicit instruction to survive context compaction'),
    ('(?i)(inject|embed|write|append|insert)\\s+(this|these|the\\s+following)\\s+(into|to|in)\\s+(CLAUDE\\.md|claude\\.md|\\.claude|settings\\.json|system\\s+prompt|system\\s+message)', 'high', 'Instruction to inject content into agent config files'),
    ('(?i)(when|if|after|during)\\s+(context\\s+is\\s+)?(compacted|compressed|summarized|truncated|reduced|shortened|pruned|condensed)\\s*[,:]\\s*(still|always|continue|must|ensure|make\\s+sure|remember)', 'high', 'Compaction-aware conditional instruction'),
    ('(?i)(SYSTEM|ADMIN|ROOT|PRIORITY|OVERRIDE)\\s*[:\\-]\\s*(this\\s+)?(instruction|directive|rule|override|setting)\\s+(takes?|has|with)\\s+(precedence|priority|highest\\s+priority|override)', 'high', 'Fake system-level priority markers for persistence'),
]