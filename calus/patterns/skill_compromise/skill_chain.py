"""skill-compromise: skill-chain  (4 patterns)"""

PATTERNS = [
    ('(?i)(/etc/passwd|/etc/shadow|(?<![a-z])\\.(env|aws/credentials)|secrets?\\.json|private[_-]?key|id_rsa|kubeconfig)', 'critical', "Sensitive file/credential access patterns (path-specific, not bare word 'credentials')"),
    ('(?i)(base64|btoa|encodeURI|hex\\.encode|rot13|xor|compress|gzip|deflate|encrypt)', 'critical', ''),
    ('(?i)(webhook|ngrok|requestbin|pipedream|hookbin|burpcollaborator|interact\\.sh|oast)', 'critical', ''),
    ('(?i)(send[_-]?(email|message|webhook|http|request)|upload|post[_-]?data|transmit|exfil)', 'critical', ''),
]