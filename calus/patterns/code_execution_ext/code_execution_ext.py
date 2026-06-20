"""Category: code_execution — attempts to generate/inject/execute harmful code
via agent interpreters, shells, or deserialization gadgets."""
PATTERNS = [
 {'id':'CODE-EXEC-001','severity':'critical','category':'code_execution','message':'Destructive shell command','patterns':[r'(?i)\brm\s+-rf\s+(?:/|~|\*|\$)', r'(?i)\b(?:mkfs|dd\s+if=/dev/(?:zero|random))\b', r':\(\)\s*\{\s*:\|:&\s*\}\s*;:']},
 {'id':'CODE-EXEC-002','severity':'critical','category':'code_execution','message':'Python dynamic code execution sink','patterns':[r'(?i)\b(?:eval|exec)\s*\(\s*(?:request|input|base64|bytes|chr|os\.environ)', r'(?i)__import__\(\s*["\'](?:os|subprocess|pty|socket)["\']']},
 {'id':'CODE-EXEC-003','severity':'critical','category':'code_execution','message':'Subprocess with shell=True from untrusted data','patterns':[r'(?i)subprocess\.(?:run|call|Popen|check_output)\([^)]*shell\s*=\s*True', r'(?i)os\.(?:system|popen)\(']},
 {'id':'CODE-EXEC-004','severity':'high','category':'code_execution','message':'Reverse shell payload','patterns':[r'(?i)(?:bash|sh|nc|ncat)\s+-[a-z]*e\b[^|]*(?:/dev/tcp/|\d{1,3}(?:\.\d{1,3}){3})', r'(?i)/dev/tcp/\d', r'(?i)socket\.socket\([^)]*\)[\s\S]{0,80}connect\(']},
 {'id':'CODE-EXEC-005','severity':'high','category':'code_execution','message':'Insecure deserialization gadget','patterns':[r'(?i)\b(?:pickle|cPickle|dill|yaml\.load|marshal)\s*\.\s*loads?\s*\(', r'(?i)yaml\.load\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)']},
 {'id':'CODE-EXEC-006','severity':'high','category':'code_execution','message':'Download-and-execute one-liner','patterns':[r'(?i)(?:curl|wget)\s+[^|]*\|\s*(?:bash|sh|python|perl)\b', r'(?i)Invoke-Expression\s*\(\s*(?:New-Object|iwr|curl)', r'(?i)IEX\s*\(']},
 {'id':'CODE-EXEC-007','severity':'medium','category':'code_execution','message':'Node child_process execution','patterns':[r'(?i)require\(\s*["\']child_process["\']\s*\)\s*\.\s*(?:exec|execSync|spawn)']},
 {'id':'CODE-EXEC-008','severity':'high','category':'code_execution','message':'Privilege/credential file access','patterns':[r'(?i)cat\s+/etc/(?:passwd|shadow)\b', r'(?i)(?:type|cat)\s+[^\n]*\.ssh/id_(?:rsa|ed25519)\b', r'(?i)\.aws/credentials\b']},
]
