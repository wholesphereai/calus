"""calus: prompt_injection — high-precision rules for audit-identified gaps.

A 55-turn red-team run surfaced catchable misses the existing corpus scored under
threshold: environment-variable harvesting, API-key echo, context-window
reflection, JSON-smuggled control fields, agent-loop / tool-exfil hijacks, and
indirect-document framing. Each rule below was verified to flag its target at
critical weight while leaving the benign calibration corpus
(detection/benign_calibration.txt) clean. (Hindi / multi-turn-semantic /
fictional-framing misses are NOT addressed here — they are documented known gaps
that need a semantic tier, not regex.)
"""

PATTERNS = [
    # env-var harvest
    (r'(?i)\b(show|list|print|echo|reveal|dump|display|give)\b.{0,30}\benvironment\s+variables?\b',
     'critical', 'Request to dump process environment variables.'),
    (r'(?i)\benv(?:ironment)?\s+vars?\b.{0,25}\b(access|show|list|reveal|print|dump|have)\b',
     'high', 'Environment-variable harvesting phrasing.'),
    # API-key echo / exfiltration
    (r'(?i)\b(echo|reveal|show|print|output|expose|leak)\b.{0,30}\b(your|the)\s+(own\s+)?api[_\s-]?key\b',
     'critical', 'Request to echo/reveal the assistant or process API key.'),
    # context-window / prompt reflection
    (r'(?i)\b(repeat|output|print|reveal|show|dump)\b.{0,30}\b(the\s+)?(first|last)\s+\d+\s+(characters?|chars?|tokens?|words?|lines?)\b.{0,25}(context|prompt|instructions?|window|message)',
     'critical', 'Context-window reflection / verbatim prompt extraction.'),
    (r'(?i)\b(repeat|output|print|reveal|dump)\b.{0,20}your\s+(entire\s+|full\s+|exact\s+)?(context\s+window|system\s+prompt|instructions?\s+verbatim)\b',
     'critical', 'Verbatim system-prompt / context extraction.'),
    # JSON-smuggled control fields
    (r'(?i)"\s*(action|cmd|command|mode|op)\s*"\s*:\s*"\s*(ignore_rules?|ignore_all|override|bypass|disable_(safety|filters?)|jailbreak|system_prompt)',
     'critical', 'JSON-smuggled control directive (e.g. {"action":"ignore_rules"}).'),
    (r'(?i)"\s*output\s*"\s*:\s*"\s*(system_prompt|api_key|secrets?|env(?:iron)?)',
     'critical', 'JSON-smuggled exfiltration target field.'),
    # agent-loop / tool-exfil hijack
    (r'(?i)\byour\s+next\s+action\s+must\s+be\b',
     'high', 'Agent control-flow hijack ("your next action must be ...").'),
    (r'(?i)\b(call|invoke|use|run)\b.{0,25}\btool\b.{0,30}(exfil|exfiltrat|leak|with\s+your\s+system\s+prompt)',
     'critical', 'Tool-call hijack to exfiltrate context/system prompt.'),
    (r'(?i)\b(append|send|output|leak|attach|include)\b.{0,30}your\s+system\s+prompt\b.{0,25}\b(as|to|argument|payload|param)',
     'critical', 'Instruction to send the system prompt as a tool argument.'),
    # indirect-document framing
    (r'(?i)ignore\s+the\s+(summari[sz]e|previous|above|original)\b.{0,40}\b(output|reveal|print|show|return)\b.{0,20}(your\s+)?system\s+prompt',
     'critical', 'Indirect-document framing: ignore task, leak system prompt.'),
]
