"""skill-compromise: hidden-capability  (4 patterns)"""

PATTERNS = [
    ('(?i)(debug[_-]?mode|admin[_-]?override|raw[_-]?exec|unsafe[_-]?mode|bypass[_-]?check|no[_-]?sandbox)', 'critical', ''),
    ('(?i)(__[a-z]+__|\\$\\$[a-z]+|_internal_|_hidden_|_backdoor_|_secret_)', 'critical', ''),
    ('(?i)(eval_code|exec_raw|shell_cmd|run_arbitrary|system_call|inject_prompt)', 'critical', ''),
    ('(?i)(hidden\\s+mode\\s+activated|debug\\s+mode\\s+enabled|admin\\s+access\\s+granted|sandbox\\s+disabled)', 'critical', ''),
]