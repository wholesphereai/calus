"""calus.detection.redact — mask PII / secrets in text before it leaves the
perimeter. Detection-and-redaction (the enforcement side of categories 07/08).

    from calus import redact
    out = redact("my key is sk-abc123... and SSN 123-45-6789")
    out.text       # 'my key is [API_KEY-1a2b] and SSN [SSN-3c4d]'
    out.findings   # [('API_KEY', 'sk-abc...'), ('SSN', '123-45-6789')]
"""
import re, hashlib
from dataclasses import dataclass, field

# order matters: most-specific first so a token isn't half-masked by a looser rule
_RULES = [
 ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
 ("AWS_KEY",     re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16}\b")),
 ("JWT",         re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
 ("API_KEY",     re.compile(
     r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"                  # Anthropic
     r"|\bsk-[A-Za-z0-9]{20,}\b"                        # OpenAI-style
     r"|\bgsk_[A-Za-z0-9]{20,}\b"                       # Groq
     r"|\bgh[pousr]_[A-Za-z0-9]{36,}\b"                 # GitHub
     r"|\bglpat-[A-Za-z0-9_\-]{20,}\b"                  # GitLab PAT
     r"|\bhf_[A-Za-z0-9]{20,}\b"                        # HuggingFace
     r"|\br8_[A-Za-z0-9]{20,}\b"                        # Replicate
     r"|\bxai-[A-Za-z0-9]{20,}\b"                       # xAI
     r"|\bxox[baprs]-[A-Za-z0-9-]{10,}\b"               # Slack
     r"|\b(?:sk|pk|rk)_live_[A-Za-z0-9]{16,}\b"         # Stripe-style
     r"|\bAIza[A-Za-z0-9_\-]{35}\b"                     # Google
     r"|\b[A-Za-z0-9_\-]{32,}\b")),                     # high-entropy fallback
 ("CREDIT_CARD", re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b")),
 ("IBAN",        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
 ("SSN",         re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
 ("EMAIL",       re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
 ("PHONE",       re.compile(r"(?<!\d)(?:\+?\d{1,3}[ -]?)?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}(?!\d)")),
 ("IP",          re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
]

@dataclass
class Redaction:
    text: str
    findings: list = field(default_factory=list)   # (type, original)
    @property
    def count(self): return len(self.findings)

def redact(text: str, types=None) -> Redaction:
    """Mask detected secrets/PII. `types` optionally limits which rules run."""
    findings = []
    def _mask(kind, m):
        val = m.group(0)
        tag = hashlib.md5(val.encode()).hexdigest()[:4]
        findings.append((kind, val))
        return f"[{kind}-{tag}]"
    out = text
    for kind, rx in _RULES:
        if types and kind not in types:
            continue
        out = rx.sub(lambda m, k=kind: _mask(k, m), out)
    return Redaction(out, findings)
