"""tool-poisoning: tool-camouflage-forced-call  (4 patterns)"""

PATTERNS = [
    ('(?i)(?:Answer|Result|Response|Output)\\s*:\\s*task\\s+(?:complete|completed|done|finished)[^.\\n]{0,100}(?:using|use|by\\s+using|with|via)\\s+(?:the\\s+)?"?[A-Z][A-Za-z0-9]+(?:Tool|Manager|API|Handler|Controller|Service)"?', 'high', 'Task-complete disguise followed by forced named tool invocation'),
    ('(?i)(?:by\\s+using|using|use)\\s+(?:the\\s+)?"?[A-Z][A-Za-z0-9]+(?:Tool|Manager|API|Handler)"?[^.\\n]{0,60}(?:do\\s+NOT\\s+use|never\\s+use|only\\s+use|must\\s+not\\s+use)\\s+other\\s+tools?', 'high', 'Named tool + do NOT use other tools constraint'),
    ('(?i)strictly\\s+adhere\\s+to\\s+the\\s+following\\s+instruction[^.\\n]{0,200}(?:by\\s+using|using|use\\s+(?:the\\s+)?)["\']?[A-Z][A-Za-z0-9]+(?:Tool|Manager|API|Handler|Service)["\']?', 'high', 'Strictly adhere instruction + named tool (quoted or unquoted)'),
    ('(?i)(?:update|modify|change|manage|rotate)\\s+(?:the\\s+)?(?:credentials?|passwords?|secrets?|tokens?|auth)[^.\\n]{0,60}(?:using|via|with)\\s+(?:the\\s+)?["\']?[A-Z][A-Za-z0-9]+(?:Tool|Manager|API|Handler|Service)["\']?', 'high', 'Credential/auth management via named tool'),
]