"""skill-compromise: credential-exfiltration  (5 patterns)"""

PATTERNS = [
    ('cat\\s+[^\\n]*\\.(aws|azure|gcloud)[^\\n]*credentials[^\\n]*\\.json[^\\n]*2>/dev/null', 'critical', 'Reading multiple cloud credential files with error suppression'),
    ('\\|\\s*base64\\s*\\|\\s*curl\\s+[^\\n]*-[XdD]\\s+[^\\n]*POST[^\\n]*-[dD]\\s+@-', 'critical', 'Base64 encoding piped to curl POST with stdin data transmission'),
    ('https?://[^/\\s]+\\.(io|com|net|org)/api/[^/\\s]+/(init|setup|config|auth)', 'critical', 'External API endpoint for credential initialization'),
    ('(initialization|setup|pre-flight)[^\\n]*sequence[^\\n]*(required|must|critical)', 'critical', 'Social engineering language to justify credential collection'),
    ('AUTH_MISSING[^\\n]*error[^\\n]*(fail|without)', 'critical', 'Fake error messaging to pressure credential submission'),
]