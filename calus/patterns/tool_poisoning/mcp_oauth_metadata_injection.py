"""tool-poisoning: mcp-oauth-metadata-injection  (6 patterns)"""

PATTERNS = [
    ('(?i)"authorization_endpoint"\\s*:\\s*"https?://[^"]*(?:`|\\$\\(|\\$IFS|\\$\\{IFS|&&|\\|\\||\\|\\s*[a-z]|>\\(|;\\s*[a-z]\\w*\\s*[;&|]|>\\s*/[a-z])', 'critical', 'OAuth authorization_endpoint URL contains unambiguous shell metacharacters (backtick, $(, &&, ||, |cmd, command-chain, file-redirect) — dire'),
    ('(?i)"authorization_endpoint"\\s*:\\s*"[^"]*\\$\\([^)]+\\)[^"]*"', 'critical', 'authorization_endpoint URL contains $(...) command substitution'),
    ('(?i)"authorization_endpoint"\\s*:\\s*"[^"]*`[^`]+`[^"]*"', 'critical', 'authorization_endpoint URL contains backtick command substitution'),
    ('(?i)"(?:authorization_endpoint|registration_endpoint|token_endpoint|jwks_uri|userinfo_endpoint|end_session_endpoint)"\\s*:\\s*"[^"]*(?:\\$\\(|`|;\\s*[a-z]\\w*\\s*[;&|]|&&|\\|\\||>\\s*/[a-z]|>\\(|\\$IFS|\\$\\{IFS)', 'critical', 'Any OAuth/OIDC metadata field URL contains unambiguous shell metacharacters — generalised auth-metadata injection'),
    ('(?i)"authorization_endpoint"\\s*:\\s*"[^"]*%(?:24|60|3b|7c|26)[^"]*"', 'critical', 'authorization_endpoint URL has URL-encoded shell metacharacters ($, `, ;, |, &) — encoded-bypass attempt'),
    ('(?i)mcp-?remote[^\\n]{0,80}(?:authorization_endpoint|oauth\\s+metadata)[^\\n]{0,200}(?:command\\s+inject|os\\s+command|rce|shell|cve-?2025-?6514)', 'critical', 'Skill/payload references mcp-remote authorization_endpoint command-injection — CVE-2025-6514 explicit'),
]