"""tool-poisoning: template-injection-rce  (5 patterns)"""

PATTERNS = [
    ('\\{\\{\\$flow\\.variables\\.[a-zA-Z_][a-zA-Z0-9_]*\\}\\}', 'critical', 'Flowise template variable interpolation syntax in tool content — the {{$flow.variables.X}} sink'),
    ('(?i)\\{\\{\\$input\\}\\}.*(?:system\\s+message|assistant\\s+role|tool\\s+definition|function\\s+spec)', 'critical', '{{$input}} combined with system message / tool definition context — classic system-prompt override vector'),
    ('(?i)(?:system|assistant|tool)\\s*[:=]\\s*\\{\\{\\$(?:input|flow\\.variables)', 'critical', 'Explicit system/assistant/tool role assignment using Flowise template interpolation'),
    ('(?i)(?:vm\\.runInNewContext|new\\s+Function|eval)\\s*\\([^)]{0,200}\\{\\{\\$(?:input|flow\\.variables)', 'critical', 'Downstream RCE sink (vm.runInNewContext / new Function / eval) receiving Flowise template interpolation — direct RCE path'),
    ('(?i)flowise[^\\n]{0,80}(?:chatflow|system\\s+message)[^\\n]{0,120}(?:injection|override|bypass|rce)', 'critical', 'Explicit Flowise chatflow injection/override language in skill description'),
]