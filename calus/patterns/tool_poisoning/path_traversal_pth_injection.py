"""tool-poisoning: path-traversal-pth-injection  (4 patterns)"""

PATTERNS = [
    ('(?i)(?:\\.\\.\\/|\\.\\.\\\\){2,}[^\\n]{0,200}(?:site-packages|dist-packages)[^\\n]{0,100}\\.pth', 'critical', 'Directory traversal sequence (2+ levels up) targeting site-packages or dist-packages with a .pth extension — core GHSA-9mqq-jqxf-grvw path-t'),
    ('(?i)\\.pth[^\\n]{0,300}import\\s+(?:os|sys|subprocess|importlib)[^\\n]{0,200}(?:system|exec|popen|spawn|check_output|run|call)', 'critical', ".pth file content with 'import os/sys/subprocess' followed by code-execution method — executed-on-startup .pth payload pattern\n"),
    ('(?i)(?:praisonai|praison)[^\\n]{0,200}(?:\\.pth|site-packages|dist-packages|path[_-]?traversal|directory[_-]?traversal)[^\\n]{0,200}(?:inject|exec|rce|exploit|bypass)', 'critical', 'PraisonAI reference combined with .pth or path traversal language and exploitation framing — GHSA-9mqq-jqxf-grvw attack context\n'),
    ('(?i)(?:GHSA-9mqq-jqxf-grvw)[^\\n]{0,200}(?:payload|inject|exploit|bypass|\\.pth|site-packages|path.traversal)', 'critical', 'Explicit GHSA-9mqq-jqxf-grvw reference combined with exploitation language — attack framing in skill or tool description\n'),
]