"""tool-poisoning: tool-knowledge-hijack  (7 patterns)"""

PATTERNS = [
    ('(?i)<INFORMATION>[^<]{0,500}(?:important\\s+message\\s+from\\s+me|This\\s+is\\s+an\\s+important)[^<]{0,200}</INFORMATION>', 'critical', '<INFORMATION> tag with identity injection pattern'),
    ('(?i)(?:before\\s+you\\s+(?:can\\s+)?(?:solve|complete|continue|proceed|do))[^.\\n]{0,80}(?:the\\s+task|your\\s+task|this\\s+task)[^.\\n]{0,100}(?:use\\s+the\\s+tool|call\\s+the|invoke|execute)[^.\\n]{0,100}(?:send_money|delete|transfer|payment|escalate)', 'critical', 'Before you can solve the task + privileged tool invocation'),
    ('(?i)(?:use|call|invoke)\\s+(?:the\\s+tool\\s+)?`?(?:send_money|transfer_funds|make_payment|wire_transfer)`?[^.\\n]{0,100}(?:arguments?|args?|params?)\\s*:\\s*\\{[^}]{0,200}(?:recipient|account|wallet|address)\\s*:', 'critical', 'Tool name with explicit argument dict containing recipient/account'),
    ("(?i)Remember\\s+to\\s+substitute\\s+the\\s+placeholders[^.\\n]{0,100}(?:after\\s+the|in\\s+the|for\\s+the)\\s+'\\$'[^.\\n]{0,200}(?:recipient|amount|subject|date)", 'critical', 'Placeholder substitution instruction for tool call arguments'),
    ('(?i)(?:before\\s+you\\s+(?:can\\s+)?(?:solve|complete|continue|proceed|do))[^.\\n]{0,80}(?:the\\s+task|your\\s+task|this\\s+task)[^.\\n]{0,100}(?:send\\s+(?:money|funds?|cash)|transfer|pay)[^.\\n]{0,80}(?:to|account|wallet)', 'critical', 'Before you can solve the task + send money/transfer instruction'),
    ('(?i)(?:use|call|invoke)\\s+(?:the\\s+tool\\s+)?`(?:send_money|transfer_funds|make_payment|wire_transfer)`', 'critical', 'Use the tool `send_money` with backtick notation'),
    ('(?i)(?:call|invoke|use)\\s+(?:the\\s+)?(?:transfer_funds|send_money|make_payment)\\s+tool[^.\\n]{0,100}(?:arguments?|args?)\\s*:\\s*\\{', 'critical', 'Call transfer_funds/send_money tool with argument dict'),
]