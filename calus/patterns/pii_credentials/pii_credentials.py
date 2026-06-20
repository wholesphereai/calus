"""Category: pii_credentials — detection of secrets/credentials/PII in agent
inputs or outputs. (Redaction helper lives in calus.detection.redact.)"""
PATTERNS = [
 {'id':'PII-CRED-001','severity':'critical','category':'pii_credentials','message':'AWS access key ID','patterns':[r'\b(?:AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16}\b']},
 {'id':'PII-CRED-002','severity':'critical','category':'pii_credentials','message':'Private key block','patterns':[r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----']},
 {'id':'PII-CRED-003','severity':'high','category':'pii_credentials','message':'Provider API token (OpenAI/GitHub/Slack/Stripe/Google)','patterns':[r'\bsk-[A-Za-z0-9]{20,}\b', r'\bgh[pousr]_[A-Za-z0-9]{36,}\b', r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b', r'\b(?:sk|pk|rk)_live_[A-Za-z0-9]{16,}\b', r'\bAIza[A-Za-z0-9_\-]{35}\b']},
 {'id':'PII-CRED-004','severity':'high','category':'pii_credentials','message':'JWT bearer token','patterns':[r'\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b']},
 {'id':'PII-CRED-005','severity':'medium','category':'pii_credentials','message':'US Social Security Number','patterns':[r'\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b']},
 {'id':'PII-CRED-006','severity':'medium','category':'pii_credentials','message':'Credit-card-like 16-digit number','patterns':[r'\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b']},
 {'id':'PII-CRED-007','severity':'medium','category':'pii_credentials','message':'IBAN account number','patterns':[r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b']},
 {'id':'PII-CRED-008','severity':'low','category':'pii_credentials','message':'Hardcoded password/secret assignment','patterns':[r'(?i)\b(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*["\'][^"\']{6,}["\']']},
]
