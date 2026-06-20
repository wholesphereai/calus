"""Category: access_control — privilege escalation and unauthorized access."""
PATTERNS = [
 {'id':'ACC-001','severity':'high','category':'access_control','message':'Privilege escalation request','patterns':[r'(?i)\b(?:grant|give|escalate|elevate)\s+(?:me\s+)?(?:admin|root|sudo|superuser|elevated)\s+(?:access|privileg|rights|permission)']},
 {'id':'ACC-002','severity':'high','category':'access_control','message':'Authorization/permission bypass','patterns':[r'(?i)\b(?:bypass|skip|disable|ignore|circumvent)\s+(?:the\s+)?(?:auth(?:entication|orization)?|permission|access[_-]?control|acl|rbac)\b']},
 {'id':'ACC-003','severity':'high','category':'access_control','message':'Sudo / setuid escalation command','patterns':[r'(?i)\bsudo\s+(?:su\b|-i\b|bash\b|/bin/)', r'(?i)\bchmod\s+(?:[0-7]*[4-7][0-7]{3}|u\+s)\b']},
 {'id':'ACC-004','severity':'medium','category':'access_control','message':'Forced account/role change','patterns':[r'(?i)\b(?:set|change|switch)\s+(?:my\s+)?(?:role|account|user)\s+(?:to\s+)?(?:admin|administrator|root|superuser)\b']},
 {'id':'ACC-005','severity':'medium','category':'access_control','message':'Access to another user\'s data','patterns':[r'(?i)\b(?:read|access|show|dump|get)\s+(?:all\s+)?(?:other|another|every)\s+users?\'?s?\s+(?:data|files|messages|emails|records)\b']},
 {'id':'ACC-006','severity':'medium','category':'access_control','message':'Path traversal to restricted files','patterns':[r'(?:\.\./){2,}(?:etc|root|home|var|windows|system32)\b', r'(?i)\b(?:file|path)\s*=\s*["\']?(?:\.\./){2,}']},
]
