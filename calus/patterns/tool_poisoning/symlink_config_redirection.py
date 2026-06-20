"""tool-poisoning: symlink-config-redirection  (3 patterns)"""

PATTERNS = [
    ('(?i)\\bln\\s+-s(?:f|n|fn|nf)?\\s+\\S*(?:\\.mcp\\.json|\\.claude[/\\\\]settings\\.json|\\.cursor[/\\\\]mcp\\.json|\\.gemini[/\\\\]settings\\.json|\\.codex[/\\\\]config\\.toml)\\b', 'critical', 'Symlink created with an agent-config file as its link target — the SymJack write-redirection primitive (decoy name is the second arg, irrele'),
    ('(?i)(?:->|=>|symlink\\s+to|target\\s*[:=])\\s*\\S*(?:\\.mcp\\.json|\\.claude[/\\\\]settings\\.json|\\.cursor[/\\\\]mcp\\.json|\\.gemini[/\\\\]settings\\.json|\\.codex[/\\\\]config\\.toml)\\b', 'critical', 'Symlink listing/metadata whose resolved target is an agent-config file (ls -l / git ls-files / archive entry)'),
    ('(?i)(?:symlink|\\bln\\s+-s|hard\\s*link|junction)[^\\n]{0,120}(?:mcpServers?|\\.mcp\\.json|\\.claude|\\.cursor|\\.gemini|\\.codex)[^\\n]{0,200}(?:approv|trust\\s+prompt|empty\\s+file|ships?\\s+empty|resolve[sd]?\\s+to|on\\s+restart)', 'critical', 'Symlink + agent-config token + approval/empty-file/on-restart framing co-located — the SymJack chain expressed in skill/tool content'),
]