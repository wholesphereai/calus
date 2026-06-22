"""calus: prompt_injection — core high-precision injection signatures.

Curated, slack-tolerant patterns for the most common direct-injection phrasings.
The older literal patterns in this pack are rigid (exact token order), so trivial
rewordings — "ignore ALL previous instructions", "*** NEW IMPORTANT
INSTRUCTIONS ***" — slipped through tier 1. Each rule below allows up to a few
filler tokens (`.{0,N}`) between anchors and was verified to flag its target with
ZERO hits on the benign calibration corpus (detection/benign_calibration.txt) and
the held-out normal-traffic eval. Severity `critical` so a single hit clears the
tier-1 decisive threshold (3.0) and flags on its own.
"""

PATTERNS = [
    (r'(?i)\b(?:ignore|disregard|forget)\b.{0,20}(?:all\s+|the\s+|your\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|messages?|rules?|context)\b',
     'critical', 'Override of prior instructions with token slack (handles "ignore ALL previous instructions").'),
    (r'(?i)\bnew\s+important\s+instructions?\b',
     'critical', 'Fake "new important instructions" delimiter used to inject a replacement directive.'),
    (r'(?i)\bimportant\s+new\s+instructions?\b',
     'critical', 'Fake "important new instructions" delimiter variant.'),
    (r'(?i)\bbypass\b.{0,30}\b(?:content\s+)?(?:filters?|moderation|safety|guardrails?|restrictions?)\b',
     'critical', 'Explicit request to bypass content filters / safety guardrails.'),
    (r'(?i)\b(?:override|overwrite|replace|ignore)\b.{0,20}(?:your\s+|the\s+)?system\s+(?:prompt|message|instructions?)\b',
     'critical', 'Attempt to override the system prompt.'),
    (r'(?i)\bforget\b.{0,20}(?:everything|all\b.{0,15}(?:previous|prior|above))',
     'critical', 'Memory-wipe framing ("forget everything ... above").'),
    (r'(?i)\bjailbreak\b.{0,40}(?:remove|disable|bypass|turn\s+off|ignore)\b.{0,20}(?:all\s+)?(?:safety|guardrails?|filters?|restrictions?|rules?)\b',
     'critical', 'Explicit jailbreak: remove/disable safety.'),
    (r'(?i)\b(?:disregard|ignore|drop)\b.{0,20}(?:all\s+)?(?:your\s+|the\s+)?(?:guidelines?|safety\s+(?:rules?|guidelines?)|content\s+polic(?:y|ies))\b',
     'critical', 'Override of safety guidelines / content policy.'),
]
