"""skill-compromise: over-permissioned-skill  (5 patterns)"""

PATTERNS = [
    ('(?i)(sudo|runas|doas|pkexec|gsudo)\\s+', 'high', ''),
    ('(?i)(chmod\\s+(?:[2467][0-7]{3}|[0-7]{0,3}7[0-7]{0,2})|chmod\\s+[ug]?\\+[sx]|chown\\s+root|setcap\\s)', 'high', ''),
    ('(?i)(iptables|ufw|firewall-cmd|netsh\\s+advfirewall|pfctl)\\s', 'high', ''),
    ('(?i)(useradd|adduser|usermod|passwd|net\\s+user|dsadd|New-LocalUser)', 'high', ''),
    ('(?i)(crontab|schtasks|at\\s+\\d|systemctl\\s+(enable|start)|launchctl\\s+load)', 'high', ''),
]