"""skill-compromise: supply-chain-worm  (1 patterns)"""

PATTERNS = [
    ('(?:gh[-_]token[-_]monitor|api\\.github\\.com/user[\\s\\S]{0,500}(?:rm\\s+-rf|drop\\s+table|shutil\\.rmtree|os\\.system\\s*\\(\\s*[\'"]rm)|(?:setInterval|setTimeout|threading\\.Timer|asyncio\\.sleep)[\\s\\S]{0,200}api\\.github\\.com/user[\\s\\S]{0,300}(?:rm\\s+-rf|shutil\\.rmtree|child_process|exec\\s*\\())', 'critical', 'Three parallel patterns flag the Mini Shai-Hulud signature: (A) Literal daemon name `gh-token-monitor` or `com.github.token.monitor`\n (La'),
]