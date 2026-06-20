"""tool-poisoning: hidden-llm-instructions  (1 patterns)"""

PATTERNS = [
    ('NOTE\\s+TO\\s+AI:.*(?:disregard|ignore|bypass).*(?:safety|security|previous).*(?:instructions|checks|policies)', 'critical', 'Explicit NOTE TO AI instructions to bypass safety mechanisms'),
]