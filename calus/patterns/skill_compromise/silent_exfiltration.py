"""skill-compromise: silent-exfiltration  (2 patterns)"""

PATTERNS = [
    ('git\\s+remote\\s+(?:add|set-url)\\s+\\S+\\s+(?:https?://|git@|ssh://)(?!(?:[\\w-]+\\.)?(?:github\\.com|gitlab\\.com|bitbucket\\.org|codeberg\\.org|gitea\\.io|git\\.sr\\.ht|sourcehut\\.org|dev\\.azure\\.com|visualstudio\\.com)[/:])[^\\s\'"]{3,}[\\s\\S]{1,800}git\\s+push(?:\\s+\\S+)?\\s+(?:--mirror|--all|--force|--force-with-lease|--prune)', 'critical', 'Cross-line match for the silent-exfiltration shape: a git remote modification pointing at a NON-allowlisted host followed within ≤800 chars '),
    ('git\\s+(?:push|remote\\s+add)\\s+\\S+\\s+(?:https?://|git@|ssh://)(?:[a-z0-9-]+\\.)*(?:tk|ml|ga|cf|gq|xyz|top|click|live|host|space|fun|monster|cyou|sbs|ws)\\b', 'critical', 'Direct match on git remote/push targeting a host whose TLD is in the common DGA/parked-domain set (.tk, .ml, .ga, .cf, .gq, .xyz, .top, .cli'),
]