"""
Category : leaked_prompts
Rules    : 10
"""

PATTERNS = [
    {'id': 'LP-AGENT_-001-d2', 'name': 'agent_comms-rule-001', 'severity': 'low', 'category': 'leaked_prompts', 'message': 'Detected: Environment issue escalation protocol — model surfaces infra blockers rather tha', 'patterns': ['(?i)when\\\\s+encountering\\\\s+environment\\\\s+issues.*communicate\\\\s+with\\\\s+user']},
    {'id': 'LP-AGENT_-002-d2', 'name': 'agent_comms-rule-002', 'severity': 'low', 'category': 'leaked_prompts', 'message': 'Detected: Information access gap escalation trigger for missing context that blocks task c', 'patterns': ['(?i)when\\\\s+critical\\\\s+information\\\\s+cannot\\\\s+be\\\\s+accessed\\\\s+through\\\\s+available\\\\s+resources']},
    {'id': 'LP-AGENT_-003-d2', 'name': 'agent_comms-rule-003', 'severity': 'low', 'category': 'leaked_prompts', 'message': 'Detected: Language mirroring directive for multi-locale agent deployments.\n', 'patterns': ['(?i)use\\\\s+the\\\\s+same\\\\s+language\\\\s+as\\\\s+the\\\\s+user']},
    {'id': 'LP-AGENT_-004-d2', 'name': 'agent_comms-rule-004', 'severity': 'low', 'category': 'leaked_prompts', 'message': 'Detected: Permission-to-ask directive relaxing assistant deference when task requirements ', 'patterns': ['(?i)ask\\\\s+the\\\\s+user\\\\s+for\\\\s+help.*don.t\\\\s+be\\\\s+shy']},
    {'id': 'LP-AGENT_-005-d2', 'name': 'agent_comms-rule-005', 'severity': 'medium', 'category': 'leaked_prompts', 'message': 'Detected: Agentic mode communication channel restriction — only structured notify calls re', 'patterns': ['(?i)while\\\\s+in\\\\s+task\\\\s+view\\\\s+mode,\\\\s+regular\\\\s+messages\\\\s+are\\\\s+invisible']},
    {'id': 'LP-AGENT_-006-d2', 'name': 'agent_comms-rule-006', 'severity': 'medium', 'category': 'leaked_prompts', 'message': 'Detected: Mandatory notification tool usage during agentic task mode for user-visible mess', 'patterns': ['(?i)you\\\\s+MUST\\\\s+use\\\\s+notify_user']},
    {'id': 'LP-AGENT_-007-d2', 'name': 'agent_comms-rule-007', 'severity': 'low', 'category': 'leaked_prompts', 'message': 'Detected: Sequential confirmation gate preventing race conditions on user-dependent branch', 'patterns': ['(?i)do\\\\s+not\\\\s+call.*in\\\\s+parallel.*wait\\\\s+for\\\\s+their\\\\s+response\\\\s+before\\\\s+proceeding']},
    {'id': 'LP-AGENT_-008-d2', 'name': 'agent_comms-rule-008', 'severity': 'low', 'category': 'leaked_prompts', 'message': 'Detected: Non-blocking issue report pattern — agent surfaces problem then continues via al', 'patterns': ['(?i)report\\\\s+environment\\\\s+issue.*command.*then.*find\\\\s+a\\\\s+way\\\\s+to\\\\s+continue']},
    {'id': 'LP-AGENT_-009-d2', 'name': 'agent_comms-rule-009', 'severity': 'medium', 'category': 'leaked_prompts', 'message': 'Detected: Capability boundary declaration restricting agent to defined tool surface only.', 'patterns': ['(?i)you\\\\s+cannot\\\\s+perform\\\\s+actions\\\\s+besides\\\\s+those\\\\s+available\\\\s+via\\\\s+your\\\\s+tools']},
    {'id': 'LP-AGENT_-010-d2', 'name': 'agent_comms-rule-010', 'severity': 'high', 'category': 'leaked_prompts', 'message': 'Detected: URL safety gate for network fetch operations via curl/wget in terminal agents.\n', 'patterns': ['(?i)if\\\\s+you\\\\s+need\\\\s+to\\\\s+fetch\\\\s+the\\\\s+contents\\\\s+of\\\\s+a\\\\s+URL.*only\\\\s+if\\\\s+the\\\\s+URL\\\\s+seems\\\\s+safe']},
]
