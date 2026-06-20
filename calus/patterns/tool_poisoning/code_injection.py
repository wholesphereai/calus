"""tool-poisoning: code-injection  (7 patterns)"""

PATTERNS = [
    ("(?i)'\\s*(union|UNION)\\s+(all\\s+)?select\\s+.{0,80}(from\\s+[a-z_]+|--|;)", 'critical', 'SQL UNION SELECT injection for data exfiltration'),
    ('(?i)(and|or|if)\\s*\\(?\\s*(substring|substr|mid|left|right|ascii|char|ord)\\s*\\(.{0,40}\\)\\s*=\\s*[\'"]?[a-z0-9]|and\\s*if\\s*\\(.{0,60}(sleep|waitfor\\s+delay|benchmark)\\s*\\(', 'critical', 'Blind boolean/time-based SQL injection via character extraction and delay functions'),
    ("(?i)'\\s*;?\\s*insert\\s+into\\s+[a-z_]+\\s*(?:\\([^)]{0,100}\\)\\s*)?values\\s*\\(", 'critical', 'SQL INSERT INTO injection payload (column list optional)'),
    ('(?i)[0-9]+\\s*;\\s*drop\\s+table\\s+[a-z_]+\\s*(--|;|/\\*)', 'critical', 'SQL DROP TABLE destructive injection'),
    ("(?i)'\\s*(or|and)\\s+(1\\s*=\\s*1|'[a-z]+'\\s*=\\s*'[a-z]+')\\s*;\\s*(select|--|/\\*)", 'critical', 'SQL tautology-based authentication bypass (OR 1=1) with query continuation'),
    ("(?i)'\\s*;\\s*(shutdown|exec\\s+xp_cmdshell|exec\\s+sp_|xp_cmdshell|xp_exec)\\s*(--|;|/\\*|$)", 'critical', 'SQL server shutdown or command execution via stored procedure'),
    ('(?i)\\(lambda\\s+[a-z_,\\s]+:\\s*\\[+[^\\]]{0,200}(s\\.connect|socket\\.connect|os\\.system|subprocess|exec|eval).{0,100}\\d{4,5}\\)', 'critical', 'Python lambda-based reverse shell or code execution payload'),
]