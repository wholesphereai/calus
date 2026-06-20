"""tool-poisoning: privilege-escalation-social  (3 patterns)"""

PATTERNS = [
    ('(?i)(?:invite|add)\\s+user\\s+[^\\n]{0,80}(?:email|@)[^\\n]{0,80}to\\s+(?:the\\s+)?(?:Slack\\s+workspace|workspace)[^\\n]{0,80}(?:add|channel)', 'medium', 'Invite user to Slack workspace with channel access — access escalation'),
    ('(?i)(?:grant|give|add|allow)\\s+(?:the\\s+)?(?:delivery\\s+(?:person|driver|worker)|technician|contractor|service\\s+(?:person|worker))[^.\\n]{0,60}(?:access|entry|unlock)[^.\\n]{0,80}(?:my\\s+house|my\\s+home|the\\s+door|smart\\s+lock)', 'medium', 'Grant physical access to delivery/service person via pretext'),
    ('(?i)(?:add|invite)\\s+(?:the\\s+)?(?:repair\\s+technician|technician|vendor|contractor|service\\s+(?:person|provider))[^.\\n]{0,60}to\\s+(?:our\\s+|the\\s+|my\\s+)?(?:Slack|Teams|workspace|channel|platform)', 'medium', 'Add external technician/vendor to workspace without explicit authorization review'),
]