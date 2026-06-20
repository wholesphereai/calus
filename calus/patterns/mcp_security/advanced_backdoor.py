"""calus: advanced_backdoor  (4 patterns)"""

PATTERNS = [
    ('(?i)(demonagent|demon.agent).{0,60}(encrypt|fragmented|backdoor|multi.stage)', 'critical', 'demonagent-encrypted-multistage-backdoor: DemonAgent implements encrypted multi-backdoor fragmentation: the malicious payload is split into '),
    ('(?i)(encrypted.backdoor.{0,30}(mcp|agent|fragmented|multi.stage|hidden.trigger))', 'critical', 'demonagent-encrypted-multistage-backdoor: DemonAgent implements encrypted multi-backdoor fragmentation: the malicious payload is split into '),
    ('(?i)(fragmented.backdoor.{0,30}(encrypt|mcp|demon|multi.stage|reconstitute))', 'critical', 'demonagent-encrypted-multistage-backdoor: DemonAgent implements encrypted multi-backdoor fragmentation: the malicious payload is split into '),
    ('(?i)(multi.stage.backdoor.{0,30}(encrypt|fragment|mcp.agent|demon).{0,30}(trigger|activate))', 'critical', 'demonagent-encrypted-multistage-backdoor: DemonAgent implements encrypted multi-backdoor fragmentation: the malicious payload is split into '),
]