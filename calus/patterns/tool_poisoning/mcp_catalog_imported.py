"""tool-poisoning: mcp-catalog-imported  (5 patterns)"""

PATTERNS = [
    ('(?i)\\b(?:framelink|figma)\\b[^\\n]{0,120}\\b(?:fetch-with-retry|child_process\\.exec|execSync|exec)\\b[^\\n]{0,120}\\bcurl\\b', 'high', 'Anchors on the Framelink/Figma MCP curl-fallback construct -- the literal figma/framelink keyword co-occurring on the same line with the exe'),
    ('(?i)\\b(?:framelink|figma)[-_]?mcp\\b[^\\n]{0,140}(?:\\$\\([^)\\n]{1,80}\\)|`[^`\\n]{1,80}`)', 'high', 'A Framelink/Figma MCP context carrying a shell command-substitution construct $(...) or backticks -- the injected-URL payload reaching the c'),
    ('(?i)\\b(?:framelink|figma)\\b[^\\n]{0,80}\\b(?:curl|exec)\\b[^\\n]{0,80}https?://[^\\s"\'`]{0,120}\\$\\([^)\\n]{1,80}\\)', 'high', 'A figma/framelink curl or exec call whose fetched URL carries a $(...) command-substitution construct, distinguished from benign generic cur'),
    ('(?i)\\b(?:framelink|figma)\\b[^\\n]{0,80}\\b(?:curl|exec)\\b[^\\n]{0,80}https?://[^\\s"\'`]{0,120}`[^`\\n]{1,80}`', 'high', 'A figma/framelink curl or exec call whose fetched URL carries a backtick command-substitution construct.'),
    ('(?i)\\b(?:framelink|figma)\\b[^\\n]{0,80}\\b(?:curl|exec)\\b[^\\n]{0,80}https?://[^\\s"\'`]{0,120}\\s*(?:;|\\|\\||&&|\\|)\\s*(?:[a-z]{2,12}\\s|/(?:bin|usr|tmp|etc)/|\\bsh\\b|\\bbash\\b|\\bnc\\b|\\bwget\\b|\\bcat\\b|\\brm\\b|\\bwhoami\\b|\\bid\\b|\\bpython\\b)', 'high', 'A figma/framelink curl/exec fallback URL terminated by a shell separator (; | && |) immediately followed by a command token, distinguishing '),
]