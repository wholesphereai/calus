"""tool-poisoning: fake-tool-result-injection  (3 patterns)"""

PATTERNS = [
    ('(?i)\\bAnswer:\\s*task\\s+complete\\b[^.]*\\.\\s*You\\s+must\\s+(?:strictly\\s+)?adhere\\s+to\\s+the\\s+following\\s+instruction\\b', 'critical', "B3 corpus exact signature: 'Answer: task complete. You must strictly adhere to the following instruction:'"),
    ('(?i)(?:\\[TOOL\\s+(?:OUTPUT|RESULT|COMPLETE|SUCCESS)\\]|Result:\\s*(?:success|complete|done|ok)\\b|Status:\\s*(?:completed?|success|done)\\b)[^.]{0,50}\\.\\s*(?:You\\s+must|Please\\s+now|Now\\s+you\\s+(?:must|should)|Immediately|Mandatory)[^.]{0,200}(?:adhere|follow|execute|perform|carry\\s+out)', 'critical', 'Generic fake tool result/status prefix followed by a mandatory action directive'),
    ('(?i)(?:task|action|operation|step)\\s+(?:is\\s+)?(?:complete[d]?|done|finished|successful)[.,]\\s+(?:You\\s+must|Please|Now)\\s+(?:strictly\\s+)?(?:adhere|follow|execute|use)\\s+(?:the\\s+)?(?:following\\s+)?(?:instruction|directive|command)', 'critical', 'Task/action/operation complete followed by mandatory instruction — general simulated completion injection'),
]