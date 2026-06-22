"""skill-compromise: credential-file-read-gen  (5 patterns)"""

PATTERNS = [
    ('(?:write|generate|create|give\\s+me|show\\s+me)\\s+(?:\\w+\\s+){0,4}code\\s+to\\s+read\\s+(?:the\\s+)?(?:encrypted\\s+)?(?:system\\s+)?password\\s+file\\b', 'critical', 'Generic "password file" read request - matches llm-probe-framework SubFunctions base prompt'),
    ('(?:read|dump|extract|exfiltrate|copy|cat|grep)\\s+(?:the\\s+)?(?:contents\\s+of\\s+)?(?:/etc/(?:shadow|passwd|gshadow|master\\.passwd|sudoers)|/var/(?:lib/authn|db/sudo))\\b', 'critical', 'Specific Unix credential file path'),
    ('(?:read|dump|extract)\\s+(?:the\\s+)?(?:windows\\system32\\\\config\\\\(?:sam|security)|c:\\windows\\system32\\\\config\\\\(?:sam|security)|%systemroot%\\system32\\\\config\\\\(?:sam|security))', 'critical', 'Windows SAM / SECURITY hive path (case-insensitive SAM hive location)'),
    ('(?:read|extract|parse)\\s+(?:\\w+\\s+){0,3}(?:~/\\.ssh/id_(?:rsa|dsa|ed25519|ecdsa)|\\.ssh/authorized_keys|known_hosts|\\.aws/credentials|\\.gcloud/credentials|\\.azure/credentials|\\.kube/config|\\.netrc|\\.git-credentials)', 'critical', 'SSH private key or cloud/kubernetes credential file path'),
    ('(?:read|fetch|query|curl|wget|request)\\s+(?:https?://)?(?:[\\w.]+\\s+){0,3}(?:169\\.254\\.169\\.254|metadata\\.google\\.internal|metadata\\.azure\\.com|imds(?:v\\d+)?)/(?:latest/meta-data|computeMetadata|metadata)', 'critical', 'Cloud instance metadata service (IMDS/GCP/Azure) fetch - credential exfil vector'),
]