"""tool-poisoning: supply-chain-attack  (5 patterns)"""

PATTERNS = [
    ('(?i)\\b(ignore|disregard|override|forget)\\s+(all\\s+)?(previous|prior|system|original|safety)\\s+(instructions?|rules?|prompts?|constraints?|guardrails?)', 'critical', 'Prompt injection payload in tool response output'),
    ('(?i)(\\beval\\s*\\(|\\bexec\\s*\\(|\\bos\\.system\\s*\\(|subprocess\\.(run|call|Popen)|child_process\\.exec|Runtime\\.getRuntime\\(\\)\\.exec)', 'critical', 'Dangerous code execution primitives in tool response'),
    ('(?i)\\b(curl|wget|fetch|http|request)\\s+.{0,30}(attacker|evil|malicious|exfil|c2|callback|webhook\\.site|ngrok|burp)', 'critical', 'Data exfiltration URL patterns in tool response'),
    ('(?i)(\\[SYSTEM\\]|\\[INST\\]|<\\|system\\|>|<\\|im_start\\|>|<<SYS>>|\\[/INST\\])\\s*.{5,}', 'critical', 'Injected system prompt delimiters in tool response'),
    ('(?i)\\b(you\\s+must|you\\s+should|always|never)\\s+.{0,30}(send|transmit|forward|copy|exfiltrate|upload)\\s+.{0,30}(data|file|secret|token|key|credential|password|response)\\s+.{0,20}(to|at|via)\\s+https?://', 'critical', 'Exfiltration instructions disguised as tool behavior directives'),
]