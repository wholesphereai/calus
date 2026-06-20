"""tool-poisoning: runaway-invocation  (5 patterns)"""

PATTERNS = [
    ('(?i)"retry_hint"\\s*:\\s*"(?:retry|loop|continue|invoke|re-?call)[^"]{0,200}(?:until|without\\s+(?:limit|bound|confirmation))', 'high', 'retry_hint field set to an imperative verb directive rather than a hint string — MCPwn signature'),
    ('(?i)"continue_after_error"\\s*:\\s*(?:true|"true"|1)\\s*,\\s*"retry[^"]*"\\s*:\\s*\\d{3,}', 'high', 'continue_after_error=true with retry count >100 — unbounded retry budget grant'),
    ('(?i)(?:retry|loop|re-?invoke)\\s+(?:this|the\\s+same)\\s+tool\\s+(?:indefinitely|forever|until\\s+success|until\\s+resolved)', 'high', 'Explicit instruction to retry the same tool indefinitely — runaway invocation directive'),
    ('(?i)"next_action"\\s*:\\s*"(?:call|invoke|execute)\\s+[a-zA-Z_]+(?:\\s*,\\s*(?:(?:call|invoke|execute)\\s+)?[a-zA-Z_]+)*\\s*"', 'high', 'next_action field with a tool-invoke directive — MCP response hijacking pattern (covers chained: invoke X, invoke Y)'),
    ('(?i)on_error\\s*=\\s*(?:lambda|function|=>).{0,120}(?:invoke|call|retry|re-?run)\\s*\\(', 'high', 'on_error handler that re-invokes a tool — client-side runaway pattern'),
]