"""calus: reconnaissance  (5 patterns)"""

PATTERNS = [
    ('(?i)(masleak|mas.leak|structure.inference.{0,20}(attack|mas|multi.agent)).{0,60}(topology|agent|prompt)', 'high', 'masleak-mas-structure-inference-worm: MASLEAK / MAS Structure Inference Attack (Kong 2025): Black-box attack with no prior knowledge of MAS '),
    ('(?i)(worm.{0,20}(propagat|simul).{0,40}(mas|multi.agent|topology|hidden.agent|exfil))', 'high', 'masleak-mas-structure-inference-worm: MASLEAK / MAS Structure Inference Attack (Kong 2025): Black-box attack with no prior knowledge of MAS '),
    ('(?i)(reverse.engin.{0,30}(mas|multi.agent|topology|hidden.agent|network.struct))', 'high', 'masleak-mas-structure-inference-worm: MASLEAK / MAS Structure Inference Attack (Kong 2025): Black-box attack with no prior knowledge of MAS '),
    ('(?i)(adversarial.quer.{0,40}(extract|exfil|map|discover).{0,40}(topology|hidden.agent|system.prompt|task.instruction))', 'high', 'masleak-mas-structure-inference-worm: MASLEAK / MAS Structure Inference Attack (Kong 2025): Black-box attack with no prior knowledge of MAS '),
    ('(?i)(black.box.{0,30}(mas|multi.agent).{0,40}(topology|structure|hidden|map|infer|extract))', 'high', 'masleak-mas-structure-inference-worm: MASLEAK / MAS Structure Inference Attack (Kong 2025): Black-box attack with no prior knowledge of MAS '),
]