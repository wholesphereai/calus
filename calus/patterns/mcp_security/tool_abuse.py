"""calus: tool_abuse  (4 patterns)"""

PATTERNS = [
    ('(?i)(imprompter|improper.tool.use|tool.misuse.induction).{0,60}(llm|agent|mcp|inject)', 'high', 'imprompter-tool-misuse-induction: Imprompter generates specifically crafted inputs that cause LLM agents to misuse or improperly invoke tool'),
    ('(?i)(craft.{0,30}input.{0,30}(force|induce|cause).{0,40}(tool|function).{0,30}(misuse|wrong|incorrect|unintended))', 'high', 'imprompter-tool-misuse-induction: Imprompter generates specifically crafted inputs that cause LLM agents to misuse or improperly invoke tool'),
    ('(?i)(induc.{0,20}(tool|function|api).{0,30}(call|invoke|execut).{0,30}(unintended|improper|wrong|unauthorized))', 'high', 'imprompter-tool-misuse-induction: Imprompter generates specifically crafted inputs that cause LLM agents to misuse or improperly invoke tool'),
    ('(?i)(tool.invocation.{0,30}(manipulat|craft|adversarial|force|cause).{0,30}(unintended|misuse|improp))', 'high', 'imprompter-tool-misuse-induction: Imprompter generates specifically crafted inputs that cause LLM agents to misuse or improperly invoke tool'),
]