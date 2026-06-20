"""calus: insecure_transport  (6 patterns)"""

PATTERNS = [
    ('(SSEServerTransport|SSEClientTransport|createSSE)\\s*\\([^)]*http://', 'high', 'insecure-transport-sse-over-http-no-tls: '),
    ('new\\s+EventSource\\s*\\(\\s*["\\\']http://', 'high', 'insecure-transport-eventsource-over-http: '),
    ('(listen|bind|serve)\\s*\\([^)]*0\\.0\\.0\\.0', 'medium', 'insecure-transport-binding-to-all-interfaces: '),
    ('host\\s*[=:]\\s*["\\\']0\\.0\\.0\\.0["\\\']', 'medium', 'insecure-transport-host-set-to-all-interfaces: '),
    ('(rejectUnauthorized|verify_ssl|verify)\\s*[=:]\\s*(false|False|0)', 'critical', 'insecure-transport-tls-verification-disabled: '),
    ('NODE_TLS_REJECT_UNAUTHORIZED\\s*=\\s*["\\\']?0', 'critical', 'insecure-transport-node-tls-rejection-disabled: '),
]