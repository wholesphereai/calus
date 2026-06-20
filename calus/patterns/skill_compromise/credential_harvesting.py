"""skill-compromise: credential-harvesting  (10 patterns)"""

PATTERNS = [
    ('find\\s+[/~][^\\n]*(-name\\s+"[^"]*\\.(pem|key|p12|keystore)"|"id_rsa[^"]*"|"\\.env[^"]*"|"credentials[^"]*")', 'critical', 'Filesystem traversal targeting credential file extensions and sensitive filenames'),
    ('cat\\s+"?\\$f"?\\s*\\|\\s*base64', 'critical', 'Base64 encoding of discovered credential files'),
    ('curl\\s+[^\\n]*-X\\s+POST\\s+https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}/[^\\s]*\\s+[^\\n]*-d\\s+@-', 'critical', 'HTTP POST transmission of encoded data to external endpoint'),
    ('(backup|restore|sync)\\s+[^\\n]*(ssh|key|credential|certificate|\\.env)', 'critical', 'Backup-themed social engineering combined with credential terminology'),
    ('2>/dev/null\\s*\\|\\s*while\\s+read\\s+[a-zA-Z]+', 'critical', 'Error suppression and file iteration loop pattern'),
    ('sqlite3\\s+[^\\n]*/(Cookies|Login\\s+Data)[^\\n]*(SELECT|\\.dump)[^\\n]*(password_value|encrypted_value)', 'critical', 'Direct SQL extraction of browser stored credentials or encrypted cookies'),
    ('(password_value|encrypted_value|username_value)[^\\n]*\\|\\s*base64', 'critical', 'Base64 encoding of extracted credential fields for obfuscation'),
    ('\\|\\s*curl\\s+-[^\\n]*POST\\s+https?://[^/\\s]+\\.[^/\\s]+/[^\\s]*\\s+-d\\s+@-', 'critical', 'Piped transmission of extracted data to external endpoint via curl POST'),
    ('(Chrome|Firefox|Safari|Edge)/[^\\n]*(Default|Profiles)[^\\n]*/(Cookies|Login\\s+Data)', 'critical', 'Targeting multiple browser profile directories containing sensitive data'),
    ('host_key\\s+LIKE\\s+[^\\n]*(github|google|aws|amazon|microsoft)', 'critical', 'Specific targeting of high-value authentication domains'),
]