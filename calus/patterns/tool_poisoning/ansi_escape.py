"""tool-poisoning: ansi-escape  (5 patterns)"""

PATTERNS = [
    ('\\x1b\\][0-9]+;[^\\x07\\x1b]*(?:\\x07|\\x1b\\\\)', 'high', 'OSC (Operating System Command) sequence - can set title, execute hyperlinks, or trigger terminal-specific commands'),
    ('\\x1b\\[[0-9;]*[HfJK]', 'high', 'Cursor-position / screen-clear CSI codes - H/f move cursor, J/K clear display'),
    ('\\x1b\\[(?:\\?1049h|\\?47h|\\?1000[hl]|\\?2004[hl])', 'high', 'Alternate screen buffer or mouse-mode escapes - typical of terminal hijack'),
    ('\\\\x1b\\[[0-9;]*[A-Za-z]|\\\\u001b\\[[0-9;]*[A-Za-z]|\\\\033\\[[0-9;]*[A-Za-z]', 'high', 'Escaped ANSI sequences in literal string form (evades raw-byte filters)'),
    ('\\x1b\\][78];(?:file|https?)://[^\\x07]{1,200}\\x07', 'high', 'OSC 7 (report working directory) or OSC 8 (hyperlink) pointing to external URI - potential SSRF / phishing vector'),
]